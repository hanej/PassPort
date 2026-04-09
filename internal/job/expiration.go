package job

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"regexp"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/robfig/cron/v3"

	"github.com/hanej/passport/internal/audit"
	"github.com/hanej/passport/internal/crypto"
	"github.com/hanej/passport/internal/db"
	"github.com/hanej/passport/internal/email"
	"github.com/hanej/passport/internal/idp"
)

// PasswordExpirationNotifier scans LDAP directories for users with expiring
// passwords and sends notification emails on a cron schedule.
type PasswordExpirationNotifier struct {
	store     db.Store
	registry  *idp.Registry
	crypto    *crypto.Service
	audit     *audit.Logger
	logger    *slog.Logger
	scheduler *cron.Cron
	mu        sync.Mutex
	entries   map[string]cron.EntryID // idpID -> cron entry ID
	connector idp.LDAPConnector
}

// New creates a new PasswordExpirationNotifier.
func New(store db.Store, registry *idp.Registry, cryptoSvc *crypto.Service, auditLogger *audit.Logger, logger *slog.Logger) *PasswordExpirationNotifier {
	return &PasswordExpirationNotifier{
		store:     store,
		registry:  registry,
		crypto:    cryptoSvc,
		audit:     auditLogger,
		logger:    logger.With("component", "expiration-notifier"),
		entries:   make(map[string]cron.EntryID),
		connector: &idp.DefaultLDAPConnector{},
	}
}

// Start initializes the cron scheduler and registers jobs for all enabled configs.
// It also starts a reload ticker to pick up config changes every 5 minutes.
func (n *PasswordExpirationNotifier) Start(ctx context.Context) {
	n.scheduler = cron.New(cron.WithLogger(cron.VerbosePrintfLogger(slog.NewLogLogger(n.logger.Handler(), slog.LevelDebug))))

	n.loadSchedules(ctx)
	n.scheduler.Start()
	n.logger.Info("password expiration notifier started")

	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				n.logger.Info("password expiration notifier stopping")
				n.scheduler.Stop()
				return
			case <-ticker.C:
				n.loadSchedules(ctx)
			}
		}
	}()
}

// ReloadSchedules forces a reload of all cron schedules from the database.
func (n *PasswordExpirationNotifier) ReloadSchedules(ctx context.Context) {
	n.loadSchedules(ctx)
}

func (n *PasswordExpirationNotifier) loadSchedules(ctx context.Context) {
	n.mu.Lock()
	defer n.mu.Unlock()

	configs, err := n.store.ListEnabledExpirationConfigs(ctx)
	if err != nil {
		n.logger.Error("failed to load expiration configs", "error", err)
		return
	}

	// Build a set of desired IDP IDs
	desired := make(map[string]string) // idpID -> cronSchedule
	for _, cfg := range configs {
		desired[cfg.IDPID] = cfg.CronSchedule
	}

	// Remove entries for IDPs that are no longer enabled
	for idpID, entryID := range n.entries {
		if _, ok := desired[idpID]; !ok {
			n.scheduler.Remove(entryID)
			delete(n.entries, idpID)
			n.logger.Debug("removed expiration schedule", "idp_id", idpID)
		}
	}

	// Add or update entries
	for idpID, schedule := range desired {
		if _, exists := n.entries[idpID]; exists {
			// For simplicity, remove and re-add to handle schedule changes
			n.scheduler.Remove(n.entries[idpID])
			delete(n.entries, idpID)
		}

		capturedID := idpID // capture for closure
		entryID, err := n.scheduler.AddFunc(schedule, func() {
			runCtx := context.Background()
			count, err := n.RunForIDP(runCtx, capturedID)
			if err != nil {
				n.logger.Error("expiration job failed", "idp_id", capturedID, "error", err)
			} else {
				n.logger.Info("expiration job completed", "idp_id", capturedID, "notifications_sent", count)
			}
		})
		if err != nil {
			n.logger.Error("failed to schedule expiration job", "idp_id", idpID, "schedule", schedule, "error", err)
			continue
		}
		n.entries[idpID] = entryID
		n.logger.Debug("scheduled expiration job", "idp_id", idpID, "schedule", schedule)
	}
}

// RunForIDP scans a single IDP's directory for expiring passwords and sends notifications.
// Returns the number of notification emails sent.
func (n *PasswordExpirationNotifier) RunForIDP(ctx context.Context, idpID string) (int, error) {
	n.logger.Info("starting expiration scan", "idp_id", idpID)

	// 1. Load expiration config
	cfg, err := n.store.GetExpirationConfig(ctx, idpID)
	if err != nil || cfg == nil || !cfg.Enabled {
		return 0, fmt.Errorf("expiration config not found or disabled for %s", idpID)
	}

	// 2. Load IDP record
	record, err := n.store.GetIDP(ctx, idpID)
	if err != nil {
		return 0, fmt.Errorf("loading IDP %s: %w", idpID, err)
	}

	var idpConfig idp.Config
	if err := json.Unmarshal([]byte(record.ConfigJSON), &idpConfig); err != nil {
		return 0, fmt.Errorf("parsing IDP config: %w", err)
	}

	var idpSecrets idp.Secrets
	if len(record.SecretBlob) > 0 {
		plaintext, err := n.crypto.Decrypt(record.SecretBlob)
		if err != nil {
			return 0, fmt.Errorf("decrypting IDP secrets: %w", err)
		}
		if err := json.Unmarshal(plaintext, &idpSecrets); err != nil {
			return 0, fmt.Errorf("parsing IDP secrets: %w", err)
		}
	}

	// 3. Load SMTP config
	smtpCfg, err := n.store.GetSMTPConfig(ctx)
	if err != nil || smtpCfg == nil {
		return 0, fmt.Errorf("SMTP not configured")
	}

	// Parse SMTP config and secrets into email.Config
	emailCfg, err := n.buildEmailConfig(smtpCfg)
	if err != nil {
		return 0, fmt.Errorf("building email config: %w", err)
	}

	// 4. Load email template — check for IDP-specific template first, fall back to global.
	tmpl, err := n.store.GetEmailTemplate(ctx, "password_expiration:"+idpID)
	if err != nil || tmpl == nil {
		tmpl, err = n.store.GetEmailTemplate(ctx, "password_expiration")
		if err != nil || tmpl == nil {
			return 0, fmt.Errorf("password_expiration email template not found")
		}
		n.logger.Debug("using global password_expiration template", "idp_id", idpID)
	} else {
		n.logger.Debug("using IDP-specific password_expiration template", "idp_id", idpID)
	}

	// 5. Load exclusion filters
	filters, err := n.store.ListExpirationFilters(ctx, idpID)
	if err != nil {
		return 0, fmt.Errorf("loading exclusion filters: %w", err)
	}

	// Pre-compile regexes
	type compiledFilter struct {
		attribute string
		regex     *regexp.Regexp
	}
	var compiled []compiledFilter
	for _, f := range filters {
		re, err := regexp.Compile(f.Pattern)
		if err != nil {
			n.logger.Warn("invalid exclusion filter regex, skipping", "pattern", f.Pattern, "error", err)
			continue
		}
		compiled = append(compiled, compiledFilter{attribute: f.Attribute, regex: re})
	}

	// 6. Create LDAP connection
	conn, err := n.connector.Connect(ctx, idpConfig.Endpoint, idpConfig.Protocol, idpConfig.Timeout, idpConfig.TLSSkipVerify)
	if err != nil {
		return 0, fmt.Errorf("connecting to LDAP: %w", err)
	}
	defer conn.Close()

	if err := conn.Bind(idpSecrets.ServiceAccountUsername, idpSecrets.ServiceAccountPassword); err != nil {
		return 0, fmt.Errorf("binding to LDAP: %w", err)
	}

	// 7. Search for expiring users based on provider type
	emailAttr := idpConfig.NotificationEmailAttr
	if emailAttr == "" {
		emailAttr = "mail"
	}

	var users []ExpiringUser
	switch idp.ProviderType(record.ProviderType) {
	case idp.ProviderTypeAD:
		maxPwdAge, err := getADMaxPwdAge(conn, idpConfig.BaseDN)
		if err != nil {
			return 0, fmt.Errorf("getting AD maxPwdAge: %w", err)
		}
		n.logger.Debug("AD maxPwdAge", "duration", maxPwdAge)
		users, err = searchADExpiringUsers(conn, idpConfig.BaseDN, idpConfig.UserSearchBase, emailAttr, maxPwdAge, cfg.DaysBeforeExpiration)
		if err != nil {
			return 0, fmt.Errorf("searching AD users: %w", err)
		}
	case idp.ProviderTypeFreeIPA:
		users, err = searchFreeIPAExpiringUsers(conn, idpConfig.BaseDN, idpConfig.UserSearchBase, emailAttr, cfg.DaysBeforeExpiration)
		if err != nil {
			return 0, fmt.Errorf("searching FreeIPA users: %w", err)
		}
	default:
		return 0, fmt.Errorf("unsupported provider type: %s", record.ProviderType)
	}

	n.logger.Info("found users with expiring passwords", "idp_id", idpID, "count", len(users))

	// 8. Apply exclusion filters and send notifications
	sent := 0
	for _, user := range users {
		// Apply exclusion filters
		excluded := false
		for _, cf := range compiled {
			// Read the attribute value for this user
			attrVal := ""
			if cf.attribute == "dn" || cf.attribute == "distinguishedName" {
				attrVal = user.DN
			} else {
				// Need to read the attribute from LDAP
				val, err := readUserAttribute(conn, user.DN, cf.attribute)
				if err != nil {
					n.logger.Debug("could not read filter attribute", "dn", user.DN, "attribute", cf.attribute, "error", err)
					continue
				}
				attrVal = val
			}
			if cf.regex.MatchString(attrVal) {
				n.logger.Debug("user excluded by filter", "username", user.Username, "attribute", cf.attribute, "pattern", cf.regex.String())
				excluded = true
				break
			}
		}
		if excluded {
			continue
		}

		// Skip users without email
		if user.Email == "" {
			n.logger.Debug("user has no email, skipping", "username", user.Username)
			continue
		}

		// Render template
		data := map[string]string{
			"Username":       user.Username,
			"ProviderName":   record.FriendlyName,
			"ExpirationDate": user.ExpirationDate.Local().Format("Jan 2, 2006 3:04 PM MST"),
			"DaysRemaining":  fmt.Sprintf("%d", user.DaysRemaining),
		}

		renderedBody, err := executeTemplate(tmpl.BodyHTML, data)
		if err != nil {
			n.logger.Warn("failed to render email body", "username", user.Username, "error", err)
			continue
		}
		renderedSubject, err := executeTemplate(tmpl.Subject, data)
		if err != nil {
			n.logger.Warn("failed to render email subject", "username", user.Username, "error", err)
			continue
		}

		// Send email
		if err := email.SendHTML(emailCfg, user.Email, renderedSubject, renderedBody); err != nil {
			n.logger.Warn("failed to send expiration notification", "username", user.Username, "email", user.Email, "error", err)
			continue
		}

		n.audit.Log(ctx, &db.AuditEntry{
			Timestamp:  time.Now().UTC(),
			Username:   user.Username,
			SourceIP:   "system",
			Action:     audit.ActionExpirationNotification,
			ProviderID: idpID,
			Result:     audit.ResultSuccess,
			Details:    fmt.Sprintf("Password expiration notification sent to %s (expires %s, %d days)", user.Email, user.ExpirationDate.Local().Format("2006-01-02"), user.DaysRemaining),
		})
		sent++
	}

	n.logger.Info("expiration scan complete", "idp_id", idpID, "total_users", len(users), "notifications_sent", sent)
	return sent, nil
}

// DryRunUserResult holds the result for a single user in a dry run.
type DryRunUserResult struct {
	Username        string `json:"username"`
	DN              string `json:"dn"`
	Email           string `json:"email"`
	ExpirationDate  string `json:"expiration_date"`
	ExpirationEpoch int64  `json:"expiration_epoch"` // Unix timestamp for sorting
	DaysRemaining   int    `json:"days_remaining"`
	Excluded        bool   `json:"excluded"`
	FilterMatch     string `json:"filter_match"` // description of the matching filter, empty if not excluded
}

// DryRunResult holds the complete dry run output.
type DryRunResult struct {
	TotalUsers    int                `json:"total_users"`
	ExcludedCount int                `json:"excluded_count"`
	EligibleCount int                `json:"eligible_count"`
	Users         []DryRunUserResult `json:"users"`
}

// DryRunForIDP scans for expiring passwords and evaluates exclusion filters
// without sending any emails. Returns detailed per-user results.
func (n *PasswordExpirationNotifier) DryRunForIDP(ctx context.Context, idpID string) (*DryRunResult, error) {
	n.logger.Info("starting dry run expiration scan", "idp_id", idpID)

	// Load expiration config (allow disabled — dry run is for testing).
	cfg, err := n.store.GetExpirationConfig(ctx, idpID)
	if err != nil || cfg == nil {
		// Use defaults if no config saved yet.
		cfg = &db.ExpirationConfig{
			IDPID:                idpID,
			DaysBeforeExpiration: 14,
		}
	}

	record, err := n.store.GetIDP(ctx, idpID)
	if err != nil {
		return nil, fmt.Errorf("loading IDP %s: %w", idpID, err)
	}

	var idpConfig idp.Config
	if err := json.Unmarshal([]byte(record.ConfigJSON), &idpConfig); err != nil {
		return nil, fmt.Errorf("parsing IDP config: %w", err)
	}

	var idpSecrets idp.Secrets
	if len(record.SecretBlob) > 0 {
		plaintext, err := n.crypto.Decrypt(record.SecretBlob)
		if err != nil {
			return nil, fmt.Errorf("decrypting IDP secrets: %w", err)
		}
		if err := json.Unmarshal(plaintext, &idpSecrets); err != nil {
			return nil, fmt.Errorf("parsing IDP secrets: %w", err)
		}
	}

	// Load exclusion filters.
	filters, err := n.store.ListExpirationFilters(ctx, idpID)
	if err != nil {
		return nil, fmt.Errorf("loading exclusion filters: %w", err)
	}

	type compiledFilter struct {
		attribute   string
		regex       *regexp.Regexp
		description string
	}
	var compiled []compiledFilter
	for _, f := range filters {
		re, err := regexp.Compile(f.Pattern)
		if err != nil {
			n.logger.Warn("invalid exclusion filter regex, skipping", "pattern", f.Pattern, "error", err)
			continue
		}
		desc := f.Description
		if desc == "" {
			desc = fmt.Sprintf("%s matches /%s/", f.Attribute, f.Pattern)
		}
		compiled = append(compiled, compiledFilter{attribute: f.Attribute, regex: re, description: desc})
	}

	// Create LDAP connection.
	conn, err := n.connector.Connect(ctx, idpConfig.Endpoint, idpConfig.Protocol, idpConfig.Timeout, idpConfig.TLSSkipVerify)
	if err != nil {
		return nil, fmt.Errorf("connecting to LDAP: %w", err)
	}
	defer conn.Close()

	if err := conn.Bind(idpSecrets.ServiceAccountUsername, idpSecrets.ServiceAccountPassword); err != nil {
		return nil, fmt.Errorf("binding to LDAP: %w", err)
	}

	emailAttr := idpConfig.NotificationEmailAttr
	if emailAttr == "" {
		emailAttr = "mail"
	}

	var users []ExpiringUser
	switch idp.ProviderType(record.ProviderType) {
	case idp.ProviderTypeAD:
		maxPwdAge, err := getADMaxPwdAge(conn, idpConfig.BaseDN)
		if err != nil {
			return nil, fmt.Errorf("getting AD maxPwdAge: %w", err)
		}
		users, err = searchADExpiringUsers(conn, idpConfig.BaseDN, idpConfig.UserSearchBase, emailAttr, maxPwdAge, cfg.DaysBeforeExpiration)
		if err != nil {
			return nil, fmt.Errorf("searching AD users: %w", err)
		}
	case idp.ProviderTypeFreeIPA:
		users, err = searchFreeIPAExpiringUsers(conn, idpConfig.BaseDN, idpConfig.UserSearchBase, emailAttr, cfg.DaysBeforeExpiration)
		if err != nil {
			return nil, fmt.Errorf("searching FreeIPA users: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported provider type: %s", record.ProviderType)
	}

	// Evaluate filters per user.
	result := &DryRunResult{
		TotalUsers: len(users),
		Users:      make([]DryRunUserResult, 0, len(users)),
	}

	for _, user := range users {
		ur := DryRunUserResult{
			Username:        user.Username,
			DN:              user.DN,
			Email:           user.Email,
			ExpirationDate:  user.ExpirationDate.Local().Format("Jan 2, 2006 3:04 PM MST"),
			ExpirationEpoch: user.ExpirationDate.Unix(),
			DaysRemaining:   user.DaysRemaining,
		}

		// Check each filter.
		for _, cf := range compiled {
			attrVal := ""
			if cf.attribute == "dn" || cf.attribute == "distinguishedName" {
				attrVal = user.DN
			} else {
				val, err := readUserAttribute(conn, user.DN, cf.attribute)
				if err != nil {
					continue
				}
				attrVal = val
			}
			if cf.regex.MatchString(attrVal) {
				ur.Excluded = true
				ur.FilterMatch = cf.description
				break
			}
		}

		if ur.Excluded {
			result.ExcludedCount++
		} else {
			result.EligibleCount++
		}
		result.Users = append(result.Users, ur)
	}

	n.logger.Info("dry run complete", "idp_id", idpID, "total", result.TotalUsers, "excluded", result.ExcludedCount, "eligible", result.EligibleCount)
	return result, nil
}

func (n *PasswordExpirationNotifier) buildEmailConfig(smtpCfg *db.SMTPConfig) (email.Config, error) {
	// Parse SMTP config JSON
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
		plaintext, err := n.crypto.Decrypt(smtpCfg.SecretBlob)
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

// readUserAttribute reads a single attribute from a user DN.
func readUserAttribute(conn idp.LDAPConn, dn, attr string) (string, error) {
	searchReq := ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false, "(objectClass=*)", []string{attr}, nil)
	result, err := conn.Search(searchReq)
	if err != nil {
		return "", err
	}
	if len(result.Entries) == 0 {
		return "", fmt.Errorf("entry not found: %s", dn)
	}
	return result.Entries[0].GetAttributeValue(attr), nil
}

// executeTemplate renders a Go template string with the given data.
func executeTemplate(tmplStr string, data any) (string, error) {
	t, err := template.New("email").Parse(tmplStr)
	if err != nil {
		return "", fmt.Errorf("parsing template: %w", err)
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("executing template: %w", err)
	}
	return buf.String(), nil
}
