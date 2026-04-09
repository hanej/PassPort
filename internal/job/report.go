package job

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/hanej/passport/internal/audit"
	"github.com/hanej/passport/internal/crypto"
	"github.com/hanej/passport/internal/db"
	"github.com/hanej/passport/internal/email"
	"github.com/hanej/passport/internal/idp"
)

// ReportScheduler generates and sends password reports on a cron schedule.
// Each IDP × report-type combination gets its own independent cron entry.
type ReportScheduler struct {
	store     db.Store
	registry  *idp.Registry
	crypto    *crypto.Service
	audit     *audit.Logger
	logger    *slog.Logger
	scheduler *cron.Cron
	mu        sync.Mutex
	entries   map[string]cron.EntryID // "idpID:reportType" -> cron entry ID
	connector idp.LDAPConnector
}

// PreviewResult holds the rendered report preview.
type PreviewResult struct {
	HTML  string `json:"html"`
	Count int    `json:"count"`
}

// NewReportScheduler creates a new ReportScheduler.
func NewReportScheduler(store db.Store, registry *idp.Registry, cryptoSvc *crypto.Service, auditLogger *audit.Logger, logger *slog.Logger) *ReportScheduler {
	return &ReportScheduler{
		store:     store,
		registry:  registry,
		crypto:    cryptoSvc,
		audit:     auditLogger,
		logger:    logger.With("component", "report-scheduler"),
		entries:   make(map[string]cron.EntryID),
		connector: &idp.DefaultLDAPConnector{},
	}
}

// Start initializes the cron scheduler and registers jobs for all enabled configs.
func (rs *ReportScheduler) Start(ctx context.Context) {
	rs.scheduler = cron.New(cron.WithLogger(cron.VerbosePrintfLogger(slog.NewLogLogger(rs.logger.Handler(), slog.LevelDebug))))

	rs.loadSchedules(ctx)
	rs.scheduler.Start()
	rs.logger.Info("report scheduler started")

	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				rs.logger.Info("report scheduler stopping")
				rs.scheduler.Stop()
				return
			case <-ticker.C:
				rs.loadSchedules(ctx)
			}
		}
	}()
}

// ReloadSchedules forces a reload of all cron schedules from the database.
func (rs *ReportScheduler) ReloadSchedules(ctx context.Context) {
	rs.loadSchedules(ctx)
}

func (rs *ReportScheduler) loadSchedules(ctx context.Context) {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	configs, err := rs.store.ListEnabledReportConfigs(ctx)
	if err != nil {
		rs.logger.Error("failed to load report configs", "error", err)
		return
	}

	// desired: "idpID:reportType" -> schedule
	desired := make(map[string]string)
	for _, cfg := range configs {
		desired[cfg.IDPID+":"+cfg.ReportType] = cfg.CronSchedule
	}

	// Remove stale entries
	for key, entryID := range rs.entries {
		if _, ok := desired[key]; !ok {
			rs.scheduler.Remove(entryID)
			delete(rs.entries, key)
			rs.logger.Debug("removed report schedule", "key", key)
		}
	}

	// Add/update entries
	for key, schedule := range desired {
		if _, exists := rs.entries[key]; exists {
			rs.scheduler.Remove(rs.entries[key])
			delete(rs.entries, key)
		}

		parts := strings.SplitN(key, ":", 2)
		capturedIDPID := parts[0]
		capturedType := parts[1]

		entryID, err := rs.scheduler.AddFunc(schedule, func() {
			runCtx := context.Background()
			if err := rs.RunReportForIDP(runCtx, capturedIDPID, capturedType); err != nil {
				rs.logger.Error("report job failed", "idp_id", capturedIDPID, "report_type", capturedType, "error", err)
			} else {
				rs.logger.Info("report job completed", "idp_id", capturedIDPID, "report_type", capturedType)
			}
		})
		if err != nil {
			rs.logger.Error("failed to schedule report job", "key", key, "schedule", schedule, "error", err)
			continue
		}
		rs.entries[key] = entryID
		rs.logger.Debug("scheduled report job", "key", key, "schedule", schedule)
	}
}

// RunReportForIDP generates a single report type for an IDP and sends it via email.
func (rs *ReportScheduler) RunReportForIDP(ctx context.Context, idpID, reportType string) error {
	rs.logger.Info("starting report generation", "idp_id", idpID, "report_type", reportType)

	cfg, err := rs.store.GetReportConfig(ctx, idpID, reportType)
	if err != nil || cfg == nil {
		return fmt.Errorf("report config not found for %s/%s", idpID, reportType)
	}

	recipients := parseRecipients(cfg.Recipients)
	if len(recipients) == 0 {
		return fmt.Errorf("no recipients configured for %s/%s", idpID, reportType)
	}

	users, record, err := rs.gatherUsers(ctx, idpID, reportType, cfg.DaysBeforeExpiration, cfg.ExcludeDisabled)
	if err != nil {
		return err
	}

	if len(users) == 0 {
		rs.logger.Info("no report users found, skipping send", "idp_id", idpID, "report_type", reportType)
		return nil
	}

	smtpCfg, err := rs.store.GetSMTPConfig(ctx)
	if err != nil || smtpCfg == nil {
		return fmt.Errorf("SMTP not configured")
	}
	emailCfg, err := rs.buildEmailConfig(smtpCfg)
	if err != nil {
		return err
	}

	generatedDate := time.Now().Local().Format("Jan 2, 2006 3:04 PM MST")
	tmplType := reportTemplateType(reportType)
	tableHTML := renderReportTable(users, reportType == db.ReportTypeExpiration)

	rendered, subject, err := rs.renderReport(ctx, idpID, record.FriendlyName, tmplType, generatedDate, tableHTML, len(users))
	if err != nil {
		return err
	}

	for _, recipient := range recipients {
		if err := email.SendHTML(emailCfg, recipient, subject, rendered); err != nil {
			rs.logger.Warn("failed to send report email", "recipient", recipient, "error", err)
		}
	}

	rs.audit.Log(ctx, &db.AuditEntry{
		Timestamp:  time.Now().UTC(),
		Username:   "system",
		SourceIP:   "system",
		Action:     audit.ActionReportSent,
		ProviderID: idpID,
		Result:     audit.ResultSuccess,
		Details:    fmt.Sprintf("%s report sent to %s (%d accounts)", reportType, strings.Join(recipients, ", "), len(users)),
	})

	rs.logger.Info("report sent", "idp_id", idpID, "report_type", reportType, "count", len(users))
	return nil
}

// PreviewForIDP generates a report preview without sending email.
func (rs *ReportScheduler) PreviewForIDP(ctx context.Context, idpID, reportType string) (*PreviewResult, error) {
	rs.logger.Info("starting report preview", "idp_id", idpID, "report_type", reportType)

	cfg, err := rs.store.GetReportConfig(ctx, idpID, reportType)
	if err != nil || cfg == nil {
		cfg = &db.ReportConfig{
			IDPID:                idpID,
			ReportType:           reportType,
			DaysBeforeExpiration: 14,
			ExcludeDisabled:      true,
		}
	}

	users, record, err := rs.gatherUsers(ctx, idpID, reportType, cfg.DaysBeforeExpiration, cfg.ExcludeDisabled)
	if err != nil {
		return nil, err
	}

	generatedDate := time.Now().Local().Format("Jan 2, 2006 3:04 PM MST")
	tableHTML := renderReportTable(users, reportType == db.ReportTypeExpiration)

	rendered, _, err := rs.renderReport(ctx, idpID, record.FriendlyName, reportTemplateType(reportType), generatedDate, tableHTML, len(users))
	if err != nil {
		return nil, err
	}

	return &PreviewResult{HTML: rendered, Count: len(users)}, nil
}

// gatherUsers fetches, sorts, and filters users for a given report type.
func (rs *ReportScheduler) gatherUsers(ctx context.Context, idpID, reportType string, threshold int, excludeDisabled bool) ([]ReportUser, *db.IdentityProviderRecord, error) {
	record, err := rs.store.GetIDP(ctx, idpID)
	if err != nil {
		return nil, nil, fmt.Errorf("loading IDP %s: %w", idpID, err)
	}

	var idpConfig idp.Config
	if err := json.Unmarshal([]byte(record.ConfigJSON), &idpConfig); err != nil {
		return nil, nil, fmt.Errorf("parsing IDP config: %w", err)
	}

	var idpSecrets idp.Secrets
	if len(record.SecretBlob) > 0 {
		plaintext, err := rs.crypto.Decrypt(record.SecretBlob)
		if err != nil {
			return nil, nil, fmt.Errorf("decrypting IDP secrets: %w", err)
		}
		if err := json.Unmarshal(plaintext, &idpSecrets); err != nil {
			return nil, nil, fmt.Errorf("parsing IDP secrets: %w", err)
		}
	}

	// Load exclusion filters for this specific report type
	filters, err := rs.store.ListReportFilters(ctx, idpID, reportType)
	if err != nil {
		return nil, nil, fmt.Errorf("loading report filters: %w", err)
	}

	var compiled []compiledReportFilter
	for _, f := range filters {
		re, err := regexp.Compile(f.Pattern)
		if err != nil {
			rs.logger.Warn("invalid report filter regex, skipping", "pattern", f.Pattern, "error", err)
			continue
		}
		compiled = append(compiled, compiledReportFilter{attribute: f.Attribute, regex: re})
	}

	conn, err := rs.connector.Connect(ctx, idpConfig.Endpoint, idpConfig.Protocol, idpConfig.Timeout, idpConfig.TLSSkipVerify)
	if err != nil {
		return nil, nil, fmt.Errorf("connecting to LDAP: %w", err)
	}
	defer func() { _ = conn.Close() }()

	if err := conn.Bind(idpSecrets.ServiceAccountUsername, idpSecrets.ServiceAccountPassword); err != nil {
		return nil, nil, fmt.Errorf("binding to LDAP: %w", err)
	}

	var soonToExpire, expired []ReportUser
	switch idp.ProviderType(record.ProviderType) {
	case idp.ProviderTypeAD:
		maxPwdAge, err := getADMaxPwdAge(conn, idpConfig.BaseDN)
		if err != nil {
			return nil, nil, fmt.Errorf("getting AD maxPwdAge: %w", err)
		}
		soonToExpire, expired, err = searchADReportUsers(conn, idpConfig.BaseDN, idpConfig.UserSearchBase, maxPwdAge, threshold, excludeDisabled)
		if err != nil {
			return nil, nil, fmt.Errorf("searching AD users: %w", err)
		}
	case idp.ProviderTypeFreeIPA:
		soonToExpire, expired, err = searchFreeIPAReportUsers(conn, idpConfig.BaseDN, idpConfig.UserSearchBase, threshold)
		if err != nil {
			return nil, nil, fmt.Errorf("searching FreeIPA users: %w", err)
		}
	default:
		return nil, nil, fmt.Errorf("unsupported provider type: %s", record.ProviderType)
	}

	// Select the right set and apply filters
	var users []ReportUser
	switch reportType {
	case db.ReportTypeExpiration:
		sort.Slice(soonToExpire, func(i, j int) bool {
			return soonToExpire[i].PasswordExpires.Before(soonToExpire[j].PasswordExpires)
		})
		users = soonToExpire
	case db.ReportTypeExpired:
		sort.Slice(expired, func(i, j int) bool {
			return expired[i].AccountName < expired[j].AccountName
		})
		users = expired
	default:
		return nil, nil, fmt.Errorf("unknown report type: %s", reportType)
	}

	if len(compiled) > 0 {
		users = filterReportUsers(conn, users, compiled, rs.logger)
	}

	return users, record, nil
}

// renderReport renders a report email template, returning (html, subject, error).
func (rs *ReportScheduler) renderReport(ctx context.Context, idpID, providerName, templateType, generatedDate, tableHTML string, accountCount int) (string, string, error) {
	tmpl, err := rs.loadReportTemplate(ctx, idpID, templateType)
	if err != nil {
		return "", "", err
	}

	data := map[string]any{
		"ProviderName":  providerName,
		"GeneratedDate": generatedDate,
		"ReportTable":   template.HTML(tableHTML),
		"AccountCount":  fmt.Sprintf("%d", accountCount),
	}

	t, err := template.New("report").Parse(tmpl.BodyHTML)
	if err != nil {
		return "", "", fmt.Errorf("parsing report template: %w", err)
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", "", fmt.Errorf("executing report template: %w", err)
	}

	renderedSubject, err := executeTemplate(tmpl.Subject, data)
	if err != nil {
		return "", "", fmt.Errorf("rendering report subject: %w", err)
	}

	return buf.String(), renderedSubject, nil
}

func (rs *ReportScheduler) loadReportTemplate(ctx context.Context, idpID, templateType string) (*db.EmailTemplate, error) {
	tmpl, err := rs.store.GetEmailTemplate(ctx, templateType+":"+idpID)
	if err != nil || tmpl == nil {
		tmpl, err = rs.store.GetEmailTemplate(ctx, templateType)
		if err != nil || tmpl == nil {
			return nil, fmt.Errorf("%s email template not found", templateType)
		}
	}
	return tmpl, nil
}

func (rs *ReportScheduler) buildEmailConfig(smtpCfg *db.SMTPConfig) (email.Config, error) {
	type smtpConfigFields struct {
		Host          string `json:"host"`
		Port          string `json:"port"`
		FromAddress   string `json:"from_address"`
		FromName      string `json:"from_name"`
		UseTLS        bool   `json:"use_tls"`
		UseStartTLS   bool   `json:"use_starttls"`
		TLSSkipVerify bool   `json:"tls_skip_verify"`
		Enabled       bool   `json:"enabled"`
	}
	var fields smtpConfigFields
	if err := json.Unmarshal([]byte(smtpCfg.ConfigJSON), &fields); err != nil {
		return email.Config{}, fmt.Errorf("parsing SMTP config: %w", err)
	}
	if !fields.Enabled {
		return email.Config{}, fmt.Errorf("SMTP is not enabled")
	}

	type smtpSecrets struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	var secrets smtpSecrets
	if len(smtpCfg.SecretBlob) > 0 {
		plaintext, err := rs.crypto.Decrypt(smtpCfg.SecretBlob)
		if err != nil {
			return email.Config{}, fmt.Errorf("decrypting SMTP secrets: %w", err)
		}
		if err := json.Unmarshal(plaintext, &secrets); err != nil {
			return email.Config{}, fmt.Errorf("parsing SMTP secrets: %w", err)
		}
	}

	return email.Config{
		Host:          fields.Host,
		Port:          fields.Port,
		FromAddress:   fields.FromAddress,
		FromName:      fields.FromName,
		UseTLS:        fields.UseTLS,
		UseStartTLS:   fields.UseStartTLS,
		TLSSkipVerify: fields.TLSSkipVerify,
		Username:      secrets.Username,
		Password:      secrets.Password,
	}, nil
}

// reportTemplateType maps a report type to its email template type string.
func reportTemplateType(reportType string) string {
	switch reportType {
	case db.ReportTypeExpired:
		return "expired_accounts_report"
	default:
		return "expiration_report"
	}
}

// renderReportTable builds an HTML table from report users.
// showDaysRemaining adds a "Days Remaining" column (used for the soon-to-expire report).
func renderReportTable(users []ReportUser, showDaysRemaining bool) string {
	hasLastLogon := false
	for _, u := range users {
		if u.LastLogon != nil {
			hasLastLogon = true
			break
		}
	}

	var buf bytes.Buffer
	fmt.Fprintf(&buf, `<table style="border-collapse:collapse;width:100%%;font-family:Arial,sans-serif;font-size:14px;">`)
	buf.WriteString(`<thead><tr style="background-color:#f8f9fa;">`)
	buf.WriteString(`<th style="border:1px solid #dee2e6;padding:8px;text-align:left;">Display Name</th>`)
	buf.WriteString(`<th style="border:1px solid #dee2e6;padding:8px;text-align:left;">Account Name</th>`)
	buf.WriteString(`<th style="border:1px solid #dee2e6;padding:8px;text-align:left;">Password Last Set</th>`)
	buf.WriteString(`<th style="border:1px solid #dee2e6;padding:8px;text-align:left;">Password Expiration</th>`)
	if showDaysRemaining {
		buf.WriteString(`<th style="border:1px solid #dee2e6;padding:8px;text-align:right;">Days Remaining</th>`)
	}
	if hasLastLogon {
		buf.WriteString(`<th style="border:1px solid #dee2e6;padding:8px;text-align:left;">Last Logon</th>`)
	}
	buf.WriteString(`</tr></thead><tbody>`)

	for _, u := range users {
		buf.WriteString(`<tr>`)
		fmt.Fprintf(&buf, `<td style="border:1px solid #dee2e6;padding:8px;">%s</td>`, template.HTMLEscapeString(u.DisplayName))
		fmt.Fprintf(&buf, `<td style="border:1px solid #dee2e6;padding:8px;">%s</td>`, template.HTMLEscapeString(u.AccountName))
		fmt.Fprintf(&buf, `<td style="border:1px solid #dee2e6;padding:8px;">%s</td>`, u.PasswordLastSet.Local().Format("Jan 2, 2006 3:04 PM"))
		fmt.Fprintf(&buf, `<td style="border:1px solid #dee2e6;padding:8px;">%s</td>`, u.PasswordExpires.Local().Format("Jan 2, 2006 3:04 PM"))
		if showDaysRemaining {
			fmt.Fprintf(&buf, `<td style="border:1px solid #dee2e6;padding:8px;text-align:right;">%d</td>`, u.DaysRemaining)
		}
		if hasLastLogon {
			logonStr := ""
			if u.LastLogon != nil {
				logonStr = u.LastLogon.Local().Format("Jan 2, 2006 3:04 PM")
			}
			fmt.Fprintf(&buf, `<td style="border:1px solid #dee2e6;padding:8px;">%s</td>`, logonStr)
		}
		buf.WriteString(`</tr>`)
	}

	buf.WriteString(`</tbody></table>`)
	return buf.String()
}

// parseRecipients splits a comma-separated recipient string into trimmed email addresses.
func parseRecipients(s string) []string {
	var result []string
	for _, r := range strings.Split(s, ",") {
		r = strings.TrimSpace(r)
		if r != "" {
			result = append(result, r)
		}
	}
	return result
}
