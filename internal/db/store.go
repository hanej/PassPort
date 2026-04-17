// Copyright 2026 Jason Hane
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package db

import (
	"context"
	"time"
)

// Store aggregates all sub-store interfaces.
type Store interface {
	AdminStore
	IDPStore
	SessionStore
	AuditStore
	MappingStore
	CorrelationWarningStore
	SettingsStore
	MFAStore
	EmailTemplateStore
	ExpirationConfigStore
	ReportConfigStore
	Ping(ctx context.Context) error
	MigrationsComplete(ctx context.Context) (bool, error)
	Close() error
}

// LocalAdmin represents the bootstrap admin account.
type LocalAdmin struct {
	ID                 int64
	Username           string
	PasswordHash       string
	MustChangePassword bool
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

// AdminStore manages the local admin account.
type AdminStore interface {
	GetLocalAdmin(ctx context.Context, username string) (*LocalAdmin, error)
	CreateLocalAdmin(ctx context.Context, username, passwordHash string) (*LocalAdmin, error)
	UpdateLocalAdminPassword(ctx context.Context, username, passwordHash string, mustChange bool) error
	ListLocalAdmins(ctx context.Context) ([]LocalAdmin, error)
	// AddPasswordHistory records passwordHash in the history for username, then
	// trims history to retain only the most recent keepN entries. keepN <= 0 skips retention.
	AddPasswordHistory(ctx context.Context, username, passwordHash string, keepN int) error
	// GetPasswordHistory returns all stored password hashes for username, most-recent-first.
	GetPasswordHistory(ctx context.Context, username string) ([]string, error)
}

// IdentityProviderRecord represents an identity provider stored in the database.
type IdentityProviderRecord struct {
	ID            string
	FriendlyName  string
	Description   string
	ProviderType  string
	Enabled       bool
	LogoURL       string
	MFAProviderID *string // nullable FK to mfa_providers; nil means use default
	ConfigJSON    string
	SecretBlob    []byte
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// AttributeMapping represents a canonical-to-directory attribute mapping.
type AttributeMapping struct {
	ID            int64
	IDPID         string
	CanonicalName string
	DirectoryAttr string
}

// CorrelationRule represents a correlation rule for an IDP.
type CorrelationRule struct {
	IDPID               string
	SourceCanonicalAttr string
	TargetDirectoryAttr string
	MatchMode           string
}

// IDPStore manages identity provider configurations.
type IDPStore interface {
	ListIDPs(ctx context.Context) ([]IdentityProviderRecord, error)
	ListEnabledIDPs(ctx context.Context) ([]IdentityProviderRecord, error)
	GetIDP(ctx context.Context, id string) (*IdentityProviderRecord, error)
	CreateIDP(ctx context.Context, idp *IdentityProviderRecord) error
	UpdateIDP(ctx context.Context, idp *IdentityProviderRecord) error
	DeleteIDP(ctx context.Context, id string) error
	ToggleIDP(ctx context.Context, id string, enabled bool) error

	// Attribute mappings
	ListAttributeMappings(ctx context.Context, idpID string) ([]AttributeMapping, error)
	SetAttributeMappings(ctx context.Context, idpID string, mappings []AttributeMapping) error

	// Correlation rules
	GetCorrelationRule(ctx context.Context, idpID string) (*CorrelationRule, error)
	SetCorrelationRule(ctx context.Context, rule *CorrelationRule) error
	DeleteCorrelationRule(ctx context.Context, idpID string) error
}

// Session represents a user session.
type Session struct {
	ID                 string
	UserType           string // "local" or "provider"
	ProviderID         string
	Username           string
	IsAdmin            bool
	MustChangePassword bool
	IPAddress          string
	UserAgent          string
	FlashJSON          string
	MFAPending         bool
	MFAState           string
	MFAAttempts        int
	CreatedAt          time.Time
	ExpiresAt          time.Time
	LastActivityAt     time.Time
}

// SessionStore manages user sessions.
type SessionStore interface {
	CreateSession(ctx context.Context, s *Session) error
	GetSession(ctx context.Context, id string) (*Session, error)
	TouchSession(ctx context.Context, id string, expiresAt time.Time) error
	UpdateSessionFlash(ctx context.Context, id, flashJSON string) error
	UpdateSessionMustChangePassword(ctx context.Context, id string, mustChange bool) error
	UpdateSessionMFA(ctx context.Context, id string, mfaPending bool, mfaState string) error
	UpdateSessionMFAAttempts(ctx context.Context, id string, attempts int) error
	DeleteSession(ctx context.Context, id string) error
	PurgeExpired(ctx context.Context) (int64, error)
}

// AuditEntry represents an audit log entry.
type AuditEntry struct {
	ID           int64
	Timestamp    time.Time
	Username     string
	SourceIP     string
	Action       string
	ProviderID   string
	ProviderName string
	Result       string
	Details      string
}

// AuditFilter holds filter parameters for querying the audit log.
type AuditFilter struct {
	Username   string
	Action     string
	Result     string
	ProviderID string
	StartDate  string
	EndDate    string
	Limit      int
	Offset     int
}

// AuditStore manages the audit log.
type AuditStore interface {
	AppendAudit(ctx context.Context, entry *AuditEntry) error
	ListAudit(ctx context.Context, filter AuditFilter) ([]AuditEntry, int, error)
	PurgeAuditBefore(ctx context.Context, before time.Time) (int64, error)
	GetIDP(ctx context.Context, id string) (*IdentityProviderRecord, error)
}

// UserIDPMapping represents a user-to-IDP account link.
type UserIDPMapping struct {
	ID              int64
	AuthProviderID  string
	AuthUsername    string
	TargetIDPID     string
	TargetAccountDN string
	LinkType        string // "auto" or "manual"
	LinkedAt        time.Time
	VerifiedAt      *time.Time
}

// MappingSearchFilter holds parameters for the admin mapping search.
// Username supports '*' as a wildcard (e.g. "john*" or "*smith").
type MappingSearchFilter struct {
	ProviderID string
	Username   string
	Limit      int
	Offset     int
}

// CorrelationWarning represents a warning from the correlation engine
// (e.g. ambiguous multi-match) that should be surfaced to the user.
type CorrelationWarning struct {
	ID           int64
	AuthUsername string
	TargetIDPID  string
	WarningType  string
	Message      string
	CreatedAt    time.Time
}

// CorrelationWarningStore manages correlation warnings.
type CorrelationWarningStore interface {
	SetCorrelationWarning(ctx context.Context, w *CorrelationWarning) error
	DeleteCorrelationWarning(ctx context.Context, authUsername, targetIDPID string) error
	ListCorrelationWarnings(ctx context.Context, authUsername string) ([]CorrelationWarning, error)
}

// MappingStore manages user-to-IDP account mappings.
type MappingStore interface {
	GetMapping(ctx context.Context, authProviderID, authUsername, targetIDPID string) (*UserIDPMapping, error)
	HasMappingToTarget(ctx context.Context, authUsername, targetIDPID string) (bool, error)
	ListMappings(ctx context.Context, authProviderID, authUsername string) ([]UserIDPMapping, error)
	SearchMappings(ctx context.Context, filter MappingSearchFilter) ([]UserIDPMapping, int, error)
	UpsertMapping(ctx context.Context, m *UserIDPMapping) error
	UpdateMappingVerified(ctx context.Context, id int64, verifiedAt time.Time) error
	DeleteMapping(ctx context.Context, id int64) error
	DeleteAllMappings(ctx context.Context, authProviderID, authUsername string) (int64, error)
	// DowngradeMapping removes a mapping (sets it to unlinked by deleting the row).
	DowngradeMapping(ctx context.Context, id int64) error
	ListAllMappings(ctx context.Context) ([]UserIDPMapping, error)
}

// AdminGroup represents an admin group mapping.
type AdminGroup struct {
	ID          int64
	IDPID       string
	GroupDN     string
	Description string
	CreatedAt   time.Time
}

// SMTPConfig represents the SMTP configuration.
type SMTPConfig struct {
	ConfigJSON string
	SecretBlob []byte
	UpdatedAt  time.Time
}

// BrandingConfig represents the whitelabel branding configuration.
type BrandingConfig struct {
	AppTitle          string `json:"app_title"`
	AppAbbreviation   string `json:"app_abbreviation"`
	AppSubtitle       string `json:"app_subtitle"`
	LogoURL           string `json:"logo_url"`
	FooterText        string `json:"footer_text"`
	PrimaryColor      string `json:"primary_color"`       // hex, e.g. "#2c5282"
	PrimaryLightColor string `json:"primary_light_color"` // hex, e.g. "#3182ce"
}

// SettingsStore manages SMTP config, admin groups, and branding.
type SettingsStore interface {
	// Admin groups
	ListAdminGroups(ctx context.Context) ([]AdminGroup, error)
	CreateAdminGroup(ctx context.Context, g *AdminGroup) error
	DeleteAdminGroup(ctx context.Context, id int64) error
	GetAdminGroupsByIDP(ctx context.Context, idpID string) ([]AdminGroup, error)

	// SMTP config
	GetSMTPConfig(ctx context.Context) (*SMTPConfig, error)
	SaveSMTPConfig(ctx context.Context, cfg *SMTPConfig) error

	// Branding config
	GetBrandingConfig(ctx context.Context) (*BrandingConfig, error)
	SaveBrandingConfig(ctx context.Context, cfg *BrandingConfig) error
}

// MFAProviderRecord represents an MFA provider stored in the database.
type MFAProviderRecord struct {
	ID           string
	Name         string
	ProviderType string
	Enabled      bool
	ConfigJSON   string
	SecretBlob   []byte
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// MFAStore manages MFA provider configurations.
type MFAStore interface {
	ListMFAProviders(ctx context.Context) ([]MFAProviderRecord, error)
	GetMFAProvider(ctx context.Context, id string) (*MFAProviderRecord, error)
	GetEnabledMFAProvider(ctx context.Context) (*MFAProviderRecord, error)
	CreateMFAProvider(ctx context.Context, p *MFAProviderRecord) error
	UpdateMFAProvider(ctx context.Context, p *MFAProviderRecord) error
	DeleteMFAProvider(ctx context.Context, id string) error
	ToggleMFAProvider(ctx context.Context, id string, enabled bool) error

	// GetMFAProviderForIDP resolves the effective MFA provider for an IDP.
	// Resolution order: IDP's directly assigned provider (if enabled) →
	// default provider from mfa_settings (if enabled) → nil (no MFA).
	GetMFAProviderForIDP(ctx context.Context, idpID string) (*MFAProviderRecord, error)

	// GetDefaultMFAProviderID returns the global default MFA provider ID, or nil if unset.
	GetDefaultMFAProviderID(ctx context.Context) (*string, error)

	// SetDefaultMFAProviderID updates the global default MFA provider ID.
	// Pass nil to clear the default.
	SetDefaultMFAProviderID(ctx context.Context, id *string) error

	// GetMFALoginRequired returns whether MFA is required on login for IDP users.
	GetMFALoginRequired(ctx context.Context) (bool, error)

	// SetMFALoginRequired enables or disables the MFA-on-login requirement.
	SetMFALoginRequired(ctx context.Context, required bool) error
}

// ExpirationConfig represents the password expiration notification configuration for an IDP.
type ExpirationConfig struct {
	IDPID                string
	Enabled              bool
	CronSchedule         string
	DaysBeforeExpiration int
	UpdatedAt            time.Time
}

// ExpirationFilter represents a filter rule for password expiration notifications.
type ExpirationFilter struct {
	ID          int64
	IDPID       string
	Attribute   string
	Pattern     string
	Description string
}

// ExpirationConfigStore manages password expiration notification configurations.
type ExpirationConfigStore interface {
	GetExpirationConfig(ctx context.Context, idpID string) (*ExpirationConfig, error)
	SaveExpirationConfig(ctx context.Context, cfg *ExpirationConfig) error
	ListExpirationFilters(ctx context.Context, idpID string) ([]ExpirationFilter, error)
	SaveExpirationFilters(ctx context.Context, idpID string, filters []ExpirationFilter) error
	ListEnabledExpirationConfigs(ctx context.Context) ([]ExpirationConfig, error)
}

// EmailTemplate represents an email template stored in the database.
type EmailTemplate struct {
	ID           int64
	TemplateType string
	Subject      string
	BodyHTML     string
	UpdatedAt    time.Time
}

// EmailTemplateStore manages email templates.
type EmailTemplateStore interface {
	ListEmailTemplates(ctx context.Context) ([]EmailTemplate, error)
	GetEmailTemplate(ctx context.Context, templateType string) (*EmailTemplate, error)
	SaveEmailTemplate(ctx context.Context, t *EmailTemplate) error
	DeleteEmailTemplate(ctx context.Context, templateType string) error
}

// Report type constants.
const (
	ReportTypeExpiration = "expiration" // soon-to-expire passwords report
	ReportTypeExpired    = "expired"    // expired accounts report
)

// ReportConfig represents the configuration for a single report type for an IDP.
type ReportConfig struct {
	IDPID                string
	ReportType           string // ReportTypeExpiration or ReportTypeExpired
	Enabled              bool
	CronSchedule         string
	DaysBeforeExpiration int    // only meaningful for ReportTypeExpiration
	Recipients           string // comma-separated email addresses
	ExcludeDisabled      bool   // exclude disabled accounts (AD: UAC bitmask; FreeIPA: via UI filter)
	UpdatedAt            time.Time
}

// ReportFilter represents an exclusion filter for a report.
type ReportFilter struct {
	ID          int64
	IDPID       string
	ReportType  string
	Attribute   string
	Pattern     string
	Description string
}

// ReportConfigStore manages report configurations.
type ReportConfigStore interface {
	GetReportConfig(ctx context.Context, idpID, reportType string) (*ReportConfig, error)
	SaveReportConfig(ctx context.Context, cfg *ReportConfig) error
	ListReportFilters(ctx context.Context, idpID, reportType string) ([]ReportFilter, error)
	SaveReportFilters(ctx context.Context, idpID, reportType string, filters []ReportFilter) error
	ListEnabledReportConfigs(ctx context.Context) ([]ReportConfig, error)
	ListReportConfigsForIDP(ctx context.Context, idpID string) ([]ReportConfig, error)
}
