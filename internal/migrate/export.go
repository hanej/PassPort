package migrate

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hanej/passport/internal/crypto"
	"github.com/hanej/passport/internal/db"
	"github.com/hanej/passport/internal/mfa"
)

// ExportData is the top-level JSON structure for export and backup files.
type ExportData struct {
	Version              int                   `json:"version"`
	ExportedAt           string                `json:"exported_at"`
	SecretsEncrypted     bool                  `json:"secrets_encrypted"`
	LocalAdmins          []ExportLocalAdmin    `json:"local_admins"`
	IdentityProviders    []ExportIDP           `json:"identity_providers"`
	AdminGroups          []ExportAdminGroup    `json:"admin_groups"`
	UserMappings         []ExportMapping       `json:"user_mappings"`
	SMTPConfig           *ExportSMTP           `json:"smtp_config"`
	MFAProviders         []ExportMFAProvider   `json:"mfa_providers"`
	DefaultMFAProviderID *string               `json:"default_mfa_provider_id"`
	MFALoginRequired     bool                  `json:"mfa_login_required"`
	Branding             *db.BrandingConfig    `json:"branding"`
	EmailTemplates       []ExportEmailTemplate `json:"email_templates"`
}

// ExportLocalAdmin represents a local admin account in the export.
type ExportLocalAdmin struct {
	Username           string   `json:"username"`
	PasswordHash       string   `json:"password_hash"`
	MustChangePassword bool     `json:"must_change_password"`
	PasswordHistory    []string `json:"password_history,omitempty"`
}

// ExportIDP represents an identity provider in the export.
type ExportIDP struct {
	ID                string                   `json:"id"`
	FriendlyName      string                   `json:"friendly_name"`
	Description       string                   `json:"description"`
	ProviderType      string                   `json:"provider_type"`
	Enabled           bool                     `json:"enabled"`
	LogoURL           string                   `json:"logo_url"`
	MFAProviderID     *string                  `json:"mfa_provider_id"`
	Config            json.RawMessage          `json:"config"`
	Secrets           json.RawMessage          `json:"secrets"`
	AttributeMappings []ExportAttrMapping      `json:"attribute_mappings"`
	CorrelationRule   *ExportCorrelationRule   `json:"correlation_rule"`
	ExpirationConfig  *ExportExpirationConfig  `json:"expiration_config"`
	ExpirationFilters []ExportExpirationFilter `json:"expiration_filters"`
	ReportConfigs     []ExportReportConfig     `json:"report_configs"`
}

// ExportAttrMapping represents an attribute mapping in the export.
type ExportAttrMapping struct {
	CanonicalName string `json:"canonical_name"`
	DirectoryAttr string `json:"directory_attr"`
}

// ExportCorrelationRule represents a correlation rule in the export.
type ExportCorrelationRule struct {
	SourceCanonicalAttr string `json:"source_canonical_attr"`
	TargetDirectoryAttr string `json:"target_directory_attr"`
	MatchMode           string `json:"match_mode"`
}

// ExportExpirationConfig represents expiration configuration in the export.
type ExportExpirationConfig struct {
	Enabled              bool   `json:"enabled"`
	CronSchedule         string `json:"cron_schedule"`
	DaysBeforeExpiration int    `json:"days_before_expiration"`
}

// ExportExpirationFilter represents an expiration filter in the export.
type ExportExpirationFilter struct {
	Attribute   string `json:"attribute"`
	Pattern     string `json:"pattern"`
	Description string `json:"description"`
}

// ExportReportConfig represents a report configuration in the export.
type ExportReportConfig struct {
	ReportType           string               `json:"report_type"`
	Enabled              bool                 `json:"enabled"`
	CronSchedule         string               `json:"cron_schedule"`
	DaysBeforeExpiration int                  `json:"days_before_expiration"`
	Recipients           string               `json:"recipients"`
	ExcludeDisabled      bool                 `json:"exclude_disabled"`
	Filters              []ExportReportFilter `json:"filters"`
}

// ExportReportFilter represents a report exclusion filter in the export.
type ExportReportFilter struct {
	Attribute   string `json:"attribute"`
	Pattern     string `json:"pattern"`
	Description string `json:"description"`
}

// ExportAdminGroup represents an admin group in the export.
type ExportAdminGroup struct {
	IDPID       string `json:"idp_id"`
	GroupDN     string `json:"group_dn"`
	Description string `json:"description"`
}

// ExportMapping represents a user-to-IDP mapping in the export.
type ExportMapping struct {
	AuthProviderID  string  `json:"auth_provider_id"`
	AuthUsername    string  `json:"auth_username"`
	TargetIDPID     string  `json:"target_idp_id"`
	TargetAccountDN string  `json:"target_account_dn"`
	LinkType        string  `json:"link_type"`
	LinkedAt        string  `json:"linked_at"`
	VerifiedAt      *string `json:"verified_at"`
}

// ExportSMTP represents SMTP configuration in the export.
type ExportSMTP struct {
	Config  json.RawMessage `json:"config"`
	Secrets json.RawMessage `json:"secrets"`
}

// ExportMFAProvider represents an MFA provider in the export.
type ExportMFAProvider struct {
	ID           string          `json:"id"`
	Name         string          `json:"name"`
	ProviderType string          `json:"provider_type"`
	Enabled      bool            `json:"enabled"`
	Config       json.RawMessage `json:"config"`
	Secrets      json.RawMessage `json:"secrets"`
}

// ExportEmailTemplate represents an email template in the export.
type ExportEmailTemplate struct {
	TemplateType string `json:"template_type"`
	Subject      string `json:"subject"`
	BodyHTML     string `json:"body_html"`
}

// ImportResult tracks what was imported.
type ImportResult struct {
	LocalAdmins    int
	IDPs           int
	AdminGroups    int
	UserMappings   int
	SMTP           bool
	MFAProviders   int
	Branding       bool
	EmailTemplates int
	ReportConfigs  int
	UploadFiles    int
	Errors         []string
}

// ImportSections controls which sections to import.
type ImportSections struct {
	Admins    bool
	IDPs      bool
	Groups    bool
	Mappings  bool
	SMTP      bool
	MFA       bool
	Branding  bool
	Templates bool
	Uploads   bool
}

// AllSections returns an ImportSections with everything enabled.
func AllSections() ImportSections {
	return ImportSections{
		Admins:    true,
		IDPs:      true,
		Groups:    true,
		Mappings:  true,
		SMTP:      true,
		MFA:       true,
		Branding:  true,
		Templates: true,
		Uploads:   true,
	}
}

// BuildExport reads all configuration from the store, decrypts secrets, and returns ExportData.
func BuildExport(ctx context.Context, store db.Store, cryptoSvc *crypto.Service) (*ExportData, error) {
	data := &ExportData{
		Version:          1,
		ExportedAt:       time.Now().UTC().Format(time.RFC3339),
		SecretsEncrypted: false,
	}

	if err := buildCommon(ctx, store, data); err != nil {
		return nil, err
	}

	// Decrypt IDP secrets — build ID→index map to avoid relying on query ordering.
	idpIdx := make(map[string]int, len(data.IdentityProviders))
	for i, ei := range data.IdentityProviders {
		idpIdx[ei.ID] = i
	}
	idps, err := store.ListIDPs(ctx)
	if err != nil {
		return nil, fmt.Errorf("list IDPs: %w", err)
	}
	for _, rec := range idps {
		idx, ok := idpIdx[rec.ID]
		if !ok || len(rec.SecretBlob) == 0 {
			continue
		}
		plaintext, err := cryptoSvc.Decrypt(rec.SecretBlob)
		if err != nil {
			return nil, fmt.Errorf("decrypt IDP secrets for %s: %w", rec.ID, err)
		}
		data.IdentityProviders[idx].Secrets = json.RawMessage(plaintext)
	}

	// Decrypt SMTP secrets
	smtpCfg, err := store.GetSMTPConfig(ctx)
	if err == nil && smtpCfg != nil && data.SMTPConfig != nil {
		if len(smtpCfg.SecretBlob) > 0 {
			plaintext, err := cryptoSvc.Decrypt(smtpCfg.SecretBlob)
			if err != nil {
				return nil, fmt.Errorf("decrypt SMTP secrets: %w", err)
			}
			data.SMTPConfig.Secrets = json.RawMessage(plaintext)
		}
	}

	// Decrypt MFA secrets — build ID→index map to avoid relying on query ordering.
	mfaIdx := make(map[string]int, len(data.MFAProviders))
	for i, ep := range data.MFAProviders {
		mfaIdx[ep.ID] = i
	}
	mfaProviders, err := store.ListMFAProviders(ctx)
	if err != nil {
		return nil, fmt.Errorf("list MFA providers: %w", err)
	}
	for _, p := range mfaProviders {
		idx, ok := mfaIdx[p.ID]
		if !ok || len(p.SecretBlob) == 0 {
			continue
		}
		plaintext, err := cryptoSvc.Decrypt(p.SecretBlob)
		if err != nil {
			return nil, fmt.Errorf("decrypt MFA secrets for %s: %w", p.ID, err)
		}
		data.MFAProviders[idx].Secrets = json.RawMessage(plaintext)
	}

	return data, nil
}

// BuildBackup reads all configuration from the store, keeps secrets encrypted as base64, and returns ExportData.
func BuildBackup(ctx context.Context, store db.Store) (*ExportData, error) {
	data := &ExportData{
		Version:          1,
		ExportedAt:       time.Now().UTC().Format(time.RFC3339),
		SecretsEncrypted: true,
	}

	if err := buildCommon(ctx, store, data); err != nil {
		return nil, err
	}

	// Encode IDP secrets as base64 — build ID→index map to avoid relying on query ordering.
	idpIdx := make(map[string]int, len(data.IdentityProviders))
	for i, ei := range data.IdentityProviders {
		idpIdx[ei.ID] = i
	}
	idps, err := store.ListIDPs(ctx)
	if err != nil {
		return nil, fmt.Errorf("list IDPs: %w", err)
	}
	for _, rec := range idps {
		idx, ok := idpIdx[rec.ID]
		if !ok || len(rec.SecretBlob) == 0 {
			continue
		}
		data.IdentityProviders[idx].Secrets = json.RawMessage(`"` + base64.StdEncoding.EncodeToString(rec.SecretBlob) + `"`)
	}

	// Encode SMTP secrets as base64
	smtpCfg, err := store.GetSMTPConfig(ctx)
	if err == nil && smtpCfg != nil && data.SMTPConfig != nil {
		if len(smtpCfg.SecretBlob) > 0 {
			data.SMTPConfig.Secrets = json.RawMessage(`"` + base64.StdEncoding.EncodeToString(smtpCfg.SecretBlob) + `"`)
		}
	}

	// Encode MFA secrets as base64 — build ID→index map to avoid relying on query ordering.
	mfaIdx := make(map[string]int, len(data.MFAProviders))
	for i, ep := range data.MFAProviders {
		mfaIdx[ep.ID] = i
	}
	mfaProviders, err := store.ListMFAProviders(ctx)
	if err != nil {
		return nil, fmt.Errorf("list MFA providers: %w", err)
	}
	for _, p := range mfaProviders {
		idx, ok := mfaIdx[p.ID]
		if !ok || len(p.SecretBlob) == 0 {
			continue
		}
		data.MFAProviders[idx].Secrets = json.RawMessage(`"` + base64.StdEncoding.EncodeToString(p.SecretBlob) + `"`)
	}

	return data, nil
}

// buildCommon populates all non-secret fields of ExportData.
func buildCommon(ctx context.Context, store db.Store, data *ExportData) error {
	// 1. Local admins
	admins, err := store.ListLocalAdmins(ctx)
	if err != nil {
		return fmt.Errorf("list local admins: %w", err)
	}
	for _, a := range admins {
		ea := ExportLocalAdmin{
			Username:           a.Username,
			PasswordHash:       a.PasswordHash,
			MustChangePassword: a.MustChangePassword,
		}
		ea.PasswordHistory, _ = store.GetPasswordHistory(ctx, a.Username)
		data.LocalAdmins = append(data.LocalAdmins, ea)
	}

	// 2. Identity providers with related data
	idps, err := store.ListIDPs(ctx)
	if err != nil {
		return fmt.Errorf("list IDPs: %w", err)
	}
	for _, rec := range idps {
		ei := ExportIDP{
			ID:            rec.ID,
			FriendlyName:  rec.FriendlyName,
			Description:   rec.Description,
			ProviderType:  rec.ProviderType,
			Enabled:       rec.Enabled,
			LogoURL:       rec.LogoURL,
			MFAProviderID: rec.MFAProviderID,
			Config:        json.RawMessage(rec.ConfigJSON),
			Secrets:       json.RawMessage("{}"),
		}

		// Attribute mappings
		mappings, err := store.ListAttributeMappings(ctx, rec.ID)
		if err != nil {
			return fmt.Errorf("list attribute mappings for IDP %s: %w", rec.ID, err)
		}
		for _, m := range mappings {
			ei.AttributeMappings = append(ei.AttributeMappings, ExportAttrMapping{
				CanonicalName: m.CanonicalName,
				DirectoryAttr: m.DirectoryAttr,
			})
		}

		// Correlation rule
		rule, err := store.GetCorrelationRule(ctx, rec.ID)
		if err == nil && rule != nil {
			ei.CorrelationRule = &ExportCorrelationRule{
				SourceCanonicalAttr: rule.SourceCanonicalAttr,
				TargetDirectoryAttr: rule.TargetDirectoryAttr,
				MatchMode:           rule.MatchMode,
			}
		}

		// Expiration config
		expCfg, err := store.GetExpirationConfig(ctx, rec.ID)
		if err == nil && expCfg != nil {
			ei.ExpirationConfig = &ExportExpirationConfig{
				Enabled:              expCfg.Enabled,
				CronSchedule:         expCfg.CronSchedule,
				DaysBeforeExpiration: expCfg.DaysBeforeExpiration,
			}
		}

		// Expiration filters
		filters, err := store.ListExpirationFilters(ctx, rec.ID)
		if err == nil {
			for _, f := range filters {
				ei.ExpirationFilters = append(ei.ExpirationFilters, ExportExpirationFilter{
					Attribute:   f.Attribute,
					Pattern:     f.Pattern,
					Description: f.Description,
				})
			}
		}

		// Report configs (one per report type)
		reportCfgs, err := store.ListReportConfigsForIDP(ctx, rec.ID)
		if err == nil {
			for _, rc := range reportCfgs {
				erc := ExportReportConfig{
					ReportType:           rc.ReportType,
					Enabled:              rc.Enabled,
					CronSchedule:         rc.CronSchedule,
					DaysBeforeExpiration: rc.DaysBeforeExpiration,
					Recipients:           rc.Recipients,
					ExcludeDisabled:      rc.ExcludeDisabled,
				}
				rfilters, ferr := store.ListReportFilters(ctx, rec.ID, rc.ReportType)
				if ferr == nil {
					for _, f := range rfilters {
						erc.Filters = append(erc.Filters, ExportReportFilter{
							Attribute:   f.Attribute,
							Pattern:     f.Pattern,
							Description: f.Description,
						})
					}
				}
				ei.ReportConfigs = append(ei.ReportConfigs, erc)
			}
		}

		data.IdentityProviders = append(data.IdentityProviders, ei)
	}

	// 3. Admin groups
	groups, err := store.ListAdminGroups(ctx)
	if err != nil {
		return fmt.Errorf("list admin groups: %w", err)
	}
	for _, g := range groups {
		data.AdminGroups = append(data.AdminGroups, ExportAdminGroup{
			IDPID:       g.IDPID,
			GroupDN:     g.GroupDN,
			Description: g.Description,
		})
	}

	// 4. User mappings
	userMappings, err := store.ListAllMappings(ctx)
	if err != nil {
		return fmt.Errorf("list user mappings: %w", err)
	}
	for _, m := range userMappings {
		em := ExportMapping{
			AuthProviderID:  m.AuthProviderID,
			AuthUsername:    m.AuthUsername,
			TargetIDPID:     m.TargetIDPID,
			TargetAccountDN: m.TargetAccountDN,
			LinkType:        m.LinkType,
			LinkedAt:        m.LinkedAt.UTC().Format(time.RFC3339),
		}
		if m.VerifiedAt != nil {
			s := m.VerifiedAt.UTC().Format(time.RFC3339)
			em.VerifiedAt = &s
		}
		data.UserMappings = append(data.UserMappings, em)
	}

	// 5. SMTP config
	smtpCfg, err := store.GetSMTPConfig(ctx)
	if err == nil && smtpCfg != nil {
		data.SMTPConfig = &ExportSMTP{
			Config:  json.RawMessage(smtpCfg.ConfigJSON),
			Secrets: json.RawMessage("{}"),
		}
	}

	// 6. MFA providers
	mfaProviders, err := store.ListMFAProviders(ctx)
	if err != nil {
		return fmt.Errorf("list MFA providers: %w", err)
	}
	for _, p := range mfaProviders {
		data.MFAProviders = append(data.MFAProviders, ExportMFAProvider{
			ID:           p.ID,
			Name:         p.Name,
			ProviderType: p.ProviderType,
			Enabled:      p.Enabled,
			Config:       json.RawMessage(p.ConfigJSON),
			Secrets:      json.RawMessage("{}"),
		})
	}

	// 7. Global default MFA provider
	defaultMFAID, err := store.GetDefaultMFAProviderID(ctx)
	if err == nil {
		data.DefaultMFAProviderID = defaultMFAID
	}

	// 7a. MFA login required setting
	mfaLoginRequired, err := store.GetMFALoginRequired(ctx)
	if err == nil {
		data.MFALoginRequired = mfaLoginRequired
	}

	// 8. Branding
	branding, err := store.GetBrandingConfig(ctx)
	if err == nil && branding != nil {
		data.Branding = branding
	}

	// 9. Email templates
	templates, err := store.ListEmailTemplates(ctx)
	if err != nil {
		return fmt.Errorf("list email templates: %w", err)
	}
	for _, t := range templates {
		data.EmailTemplates = append(data.EmailTemplates, ExportEmailTemplate{
			TemplateType: t.TemplateType,
			Subject:      t.Subject,
			BodyHTML:     t.BodyHTML,
		})
	}

	return nil
}

// RunImport imports data from an ExportData structure into the store.
// If the data has encrypted secrets (backup file), blobs are stored as-is.
// If secrets are plaintext (export file), they are re-encrypted with the provided crypto service.
func RunImport(ctx context.Context, store db.Store, cryptoSvc *crypto.Service, data *ExportData, sections ImportSections) (*ImportResult, error) {
	if data.Version != 1 {
		return nil, fmt.Errorf("unsupported export version: %d (expected 1)", data.Version)
	}

	result := &ImportResult{}

	// 1. Local admins
	if sections.Admins {
		for _, a := range data.LocalAdmins {
			existing, err := store.GetLocalAdmin(ctx, a.Username)
			if err != nil && err != db.ErrNotFound {
				result.Errors = append(result.Errors, fmt.Sprintf("Failed to check admin %s: %v", a.Username, err))
				continue
			}
			if existing != nil {
				if err := store.UpdateLocalAdminPassword(ctx, a.Username, a.PasswordHash, a.MustChangePassword); err != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("Failed to update admin %s: %v", a.Username, err))
					continue
				}
			} else {
				if _, err := store.CreateLocalAdmin(ctx, a.Username, a.PasswordHash); err != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("Failed to create admin %s: %v", a.Username, err))
					continue
				}
				if !a.MustChangePassword {
					if err := store.UpdateLocalAdminPassword(ctx, a.Username, a.PasswordHash, false); err != nil {
						result.Errors = append(result.Errors, fmt.Sprintf("Failed to update admin %s must_change flag: %v", a.Username, err))
					}
				}
			}
			// Restore password history (most-recent-first; AddPasswordHistory with keepN=0 appends without trimming).
			for _, h := range a.PasswordHistory {
				if err := store.AddPasswordHistory(ctx, a.Username, h, 0); err != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("Failed to restore password history for %s: %v", a.Username, err))
				}
			}
			result.LocalAdmins++
		}
	}

	// 2. Identity providers
	if sections.IDPs {
		for _, ei := range data.IdentityProviders {
			secretBlob, err := resolveSecretBlob(data.SecretsEncrypted, ei.Secrets, cryptoSvc)
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("Failed to process secrets for IDP %s: %v", ei.ID, err))
				continue
			}

			record := &db.IdentityProviderRecord{
				ID:            ei.ID,
				FriendlyName:  ei.FriendlyName,
				Description:   ei.Description,
				ProviderType:  ei.ProviderType,
				Enabled:       ei.Enabled,
				LogoURL:       ei.LogoURL,
				MFAProviderID: ei.MFAProviderID,
				ConfigJSON:    string(ei.Config),
				SecretBlob:    secretBlob,
			}

			existing, getErr := store.GetIDP(ctx, ei.ID)
			if getErr != nil || existing == nil {
				if createErr := store.CreateIDP(ctx, record); createErr != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("Failed to create IDP %s: %v", ei.ID, createErr))
					continue
				}
			} else {
				if updateErr := store.UpdateIDP(ctx, record); updateErr != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("Failed to update IDP %s: %v", ei.ID, updateErr))
					continue
				}
			}

			// Attribute mappings
			if len(ei.AttributeMappings) > 0 {
				var dbMappings []db.AttributeMapping
				for _, am := range ei.AttributeMappings {
					dbMappings = append(dbMappings, db.AttributeMapping{
						IDPID:         ei.ID,
						CanonicalName: am.CanonicalName,
						DirectoryAttr: am.DirectoryAttr,
					})
				}
				if err := store.SetAttributeMappings(ctx, ei.ID, dbMappings); err != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("Failed to set attribute mappings for IDP %s: %v", ei.ID, err))
				}
			}

			// Correlation rule
			if ei.CorrelationRule != nil {
				rule := &db.CorrelationRule{
					IDPID:               ei.ID,
					SourceCanonicalAttr: ei.CorrelationRule.SourceCanonicalAttr,
					TargetDirectoryAttr: ei.CorrelationRule.TargetDirectoryAttr,
					MatchMode:           ei.CorrelationRule.MatchMode,
				}
				if err := store.SetCorrelationRule(ctx, rule); err != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("Failed to set correlation rule for IDP %s: %v", ei.ID, err))
				}
			}

			// Expiration config
			if ei.ExpirationConfig != nil {
				cfg := &db.ExpirationConfig{
					IDPID:                ei.ID,
					Enabled:              ei.ExpirationConfig.Enabled,
					CronSchedule:         ei.ExpirationConfig.CronSchedule,
					DaysBeforeExpiration: ei.ExpirationConfig.DaysBeforeExpiration,
				}
				if err := store.SaveExpirationConfig(ctx, cfg); err != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("Failed to save expiration config for IDP %s: %v", ei.ID, err))
				}
			}

			// Expiration filters
			if len(ei.ExpirationFilters) > 0 {
				var dbFilters []db.ExpirationFilter
				for _, f := range ei.ExpirationFilters {
					dbFilters = append(dbFilters, db.ExpirationFilter{
						IDPID:       ei.ID,
						Attribute:   f.Attribute,
						Pattern:     f.Pattern,
						Description: f.Description,
					})
				}
				if err := store.SaveExpirationFilters(ctx, ei.ID, dbFilters); err != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("Failed to save expiration filters for IDP %s: %v", ei.ID, err))
				}
			}

			// Report configs
			for _, erc := range ei.ReportConfigs {
				cfg := &db.ReportConfig{
					IDPID:                ei.ID,
					ReportType:           erc.ReportType,
					Enabled:              erc.Enabled,
					CronSchedule:         erc.CronSchedule,
					DaysBeforeExpiration: erc.DaysBeforeExpiration,
					Recipients:           erc.Recipients,
					ExcludeDisabled:      erc.ExcludeDisabled,
				}
				if err := store.SaveReportConfig(ctx, cfg); err != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("Failed to save report config (%s) for IDP %s: %v", erc.ReportType, ei.ID, err))
					continue
				}
				var dbRFilters []db.ReportFilter
				for _, f := range erc.Filters {
					dbRFilters = append(dbRFilters, db.ReportFilter{
						IDPID:       ei.ID,
						ReportType:  erc.ReportType,
						Attribute:   f.Attribute,
						Pattern:     f.Pattern,
						Description: f.Description,
					})
				}
				if err := store.SaveReportFilters(ctx, ei.ID, erc.ReportType, dbRFilters); err != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("Failed to save report filters (%s) for IDP %s: %v", erc.ReportType, ei.ID, err))
				} else {
					result.ReportConfigs++
				}
			}

			result.IDPs++
		}
	}

	// 3. Admin groups — delete existing groups for each referenced IDP before recreating,
	// so re-importing the same file is idempotent.
	if sections.Groups {
		// Collect unique IDP IDs referenced in the import data.
		idpIDs := make(map[string]struct{})
		for _, g := range data.AdminGroups {
			idpIDs[g.IDPID] = struct{}{}
		}
		for idpID := range idpIDs {
			existing, err := store.GetAdminGroupsByIDP(ctx, idpID)
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("Failed to list admin groups for IDP %s: %v", idpID, err))
				continue
			}
			for _, g := range existing {
				if err := store.DeleteAdminGroup(ctx, g.ID); err != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("Failed to delete admin group %s: %v", g.GroupDN, err))
				}
			}
		}

		for _, g := range data.AdminGroups {
			ag := &db.AdminGroup{
				IDPID:       g.IDPID,
				GroupDN:     g.GroupDN,
				Description: g.Description,
			}
			if err := store.CreateAdminGroup(ctx, ag); err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("Failed to create admin group %s: %v", g.GroupDN, err))
				continue
			}
			result.AdminGroups++
		}
	}

	// 4. User mappings
	if sections.Mappings {
		for _, em := range data.UserMappings {
			linkedAt, err := time.Parse(time.RFC3339, em.LinkedAt)
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("Failed to parse linked_at for mapping %s->%s: %v", em.AuthUsername, em.TargetIDPID, err))
				continue
			}
			m := &db.UserIDPMapping{
				AuthProviderID:  em.AuthProviderID,
				AuthUsername:    em.AuthUsername,
				TargetIDPID:     em.TargetIDPID,
				TargetAccountDN: em.TargetAccountDN,
				LinkType:        em.LinkType,
				LinkedAt:        linkedAt,
			}
			if em.VerifiedAt != nil {
				t, err := time.Parse(time.RFC3339, *em.VerifiedAt)
				if err != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("Failed to parse verified_at for mapping %s->%s: %v", em.AuthUsername, em.TargetIDPID, err))
					continue
				}
				m.VerifiedAt = &t
			}
			if err := store.UpsertMapping(ctx, m); err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("Failed to upsert mapping %s->%s: %v", em.AuthUsername, em.TargetIDPID, err))
				continue
			}
			result.UserMappings++
		}
	}

	// 5. SMTP config
	if sections.SMTP && data.SMTPConfig != nil {
		secretBlob, err := resolveSecretBlob(data.SecretsEncrypted, data.SMTPConfig.Secrets, cryptoSvc)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Failed to process SMTP secrets: %v", err))
		} else {
			cfg := &db.SMTPConfig{
				ConfigJSON: string(data.SMTPConfig.Config),
				SecretBlob: secretBlob,
			}
			if err := store.SaveSMTPConfig(ctx, cfg); err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("Failed to save SMTP config: %v", err))
			} else {
				result.SMTP = true
			}
		}
	}

	// 6. MFA providers
	if sections.MFA {
		for _, ep := range data.MFAProviders {
			secretBlob, err := resolveSecretBlob(data.SecretsEncrypted, ep.Secrets, cryptoSvc)
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("Failed to process MFA secrets for %s: %v", ep.ID, err))
				continue
			}

			// Validate Duo config
			if ep.ProviderType == "duo" {
				var duoCfg mfa.DuoConfig
				if err := json.Unmarshal(ep.Config, &duoCfg); err != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("Invalid MFA config for %s: %v", ep.ID, err))
					continue
				}
			}

			record := &db.MFAProviderRecord{
				ID:           ep.ID,
				Name:         ep.Name,
				ProviderType: ep.ProviderType,
				Enabled:      ep.Enabled,
				ConfigJSON:   string(ep.Config),
				SecretBlob:   secretBlob,
			}

			existing, getErr := store.GetMFAProvider(ctx, ep.ID)
			if getErr != nil || existing == nil {
				if createErr := store.CreateMFAProvider(ctx, record); createErr != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("Failed to create MFA provider %s: %v", ep.ID, createErr))
					continue
				}
			} else {
				if updateErr := store.UpdateMFAProvider(ctx, record); updateErr != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("Failed to update MFA provider %s: %v", ep.ID, updateErr))
					continue
				}
			}
			result.MFAProviders++
		}
	}

	// 7. Global default MFA provider
	if sections.MFA && data.DefaultMFAProviderID != nil {
		if err := store.SetDefaultMFAProviderID(ctx, data.DefaultMFAProviderID); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Failed to restore default MFA provider: %v", err))
		}
	}

	// 7a. MFA login required setting
	if sections.MFA {
		if err := store.SetMFALoginRequired(ctx, data.MFALoginRequired); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Failed to restore MFA login required setting: %v", err))
		}
	}

	// 8. Branding
	if sections.Branding && data.Branding != nil {
		if err := store.SaveBrandingConfig(ctx, data.Branding); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Failed to save branding: %v", err))
		} else {
			result.Branding = true
		}
	}

	// 9. Email templates
	if sections.Templates {
		for _, et := range data.EmailTemplates {
			t := &db.EmailTemplate{
				TemplateType: et.TemplateType,
				Subject:      et.Subject,
				BodyHTML:     et.BodyHTML,
			}
			if err := store.SaveEmailTemplate(ctx, t); err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("Failed to save email template %s: %v", et.TemplateType, err))
				continue
			}
			result.EmailTemplates++
		}
	}

	return result, nil
}

// resolveSecretBlob handles secret data based on whether the export has encrypted or plaintext secrets.
// For encrypted (backup) data: decodes base64 and returns raw bytes.
// For plaintext (export) data: encrypts the JSON with the crypto service.
func resolveSecretBlob(encrypted bool, secrets json.RawMessage, cryptoSvc *crypto.Service) ([]byte, error) {
	if len(secrets) == 0 || string(secrets) == "{}" || string(secrets) == `"{}"` {
		return nil, nil
	}

	if encrypted {
		// Backup mode: secrets is a base64-encoded string — decode it.
		var b64str string
		if err := json.Unmarshal(secrets, &b64str); err != nil {
			return nil, fmt.Errorf("unmarshal base64 secret string: %w", err)
		}
		blob, err := base64.StdEncoding.DecodeString(b64str)
		if err != nil {
			return nil, fmt.Errorf("decode base64 secret: %w", err)
		}
		return blob, nil
	}

	// Export mode: secrets is plaintext JSON — re-encrypt it.
	blob, err := cryptoSvc.Encrypt(secrets)
	if err != nil {
		return nil, fmt.Errorf("encrypt secret: %w", err)
	}
	return blob, nil
}
