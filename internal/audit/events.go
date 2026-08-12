// Package audit provides structured audit event logging.
package audit

// Event type constants for all auditable actions.
const (
	ActionLogin                  = "login"
	ActionLogout                 = "logout"
	ActionPasswordChange         = "password_change"
	ActionPasswordReset          = "password_reset"
	ActionAccountUnlock          = "account_unlock"
	ActionAccountEnable          = "account_enable"
	ActionIDPCreate              = "idp_create"
	ActionIDPUpdate              = "idp_update"
	ActionIDPDelete              = "idp_delete"
	ActionIDPToggle              = "idp_toggle"
	ActionIDPTestConnection      = "idp_test_connection"
	ActionSMTPUpdate             = "smtp_update"
	ActionSMTPTest               = "smtp_test"
	ActionAdminGroupAdd          = "admin_group_add"
	ActionAdminGroupDelete       = "admin_group_delete"
	ActionLinkAuto               = "link_auto"
	ActionLinkManual             = "link_manual"
	ActionLinkFailed             = "link_failed"
	ActionMappingReset           = "mapping_reset"
	ActionMappingResetAll        = "mapping_reset_all"
	ActionAdminPasswordChange    = "admin_password_change"
	ActionMFACreate              = "mfa_create"
	ActionMFAUpdate              = "mfa_update"
	ActionMFADelete              = "mfa_delete"
	ActionMFAToggle              = "mfa_toggle"
	ActionMFAVerify              = "mfa_verify"
	ActionEmailTemplateUpdate    = "email_template_update"
	ActionEmailTemplateReset     = "email_template_reset"
	ActionExpirationNotification = "expiration_notification"
	ActionExpiredNotification    = "expired_notification"
	ActionExpirationConfigUpdate = "expiration_config_update"
	ActionReportConfigUpdate     = "report_config_update"
	ActionReportSent             = "report_sent"

	ResultSuccess = "success"
	ResultFailure = "failure"
	// ResultWarning records an action that completed but with a caveat worth
	// keeping, such as a policy check that could not be performed.
	ResultWarning = "warning"
)

// FilterOption is one entry in the audit viewer's action filter.
type FilterOption struct {
	Group string
	Value string
	Label string
}

// FilterOptions lists every action the log can record, so the viewer's filter
// cannot drift from the constants above. Filtering matches the action exactly.
func FilterOptions() []FilterOption {
	return []FilterOption{
		{"Authentication", ActionLogin, "Login"},
		{"Authentication", ActionLogout, "Logout"},
		{"Authentication", ActionMFAVerify, "MFA Verification"},

		{"Passwords", ActionPasswordChange, "Password Change"},
		{"Passwords", ActionPasswordReset, "Password Reset"},
		{"Passwords", ActionAdminPasswordChange, "Local Admin Password Change"},

		{"Accounts", ActionAccountUnlock, "Account Unlock"},
		{"Accounts", ActionAccountEnable, "Account Enable"},

		{"Account Linking", ActionLinkAuto, "Automatic Link"},
		{"Account Linking", ActionLinkManual, "Manual Link"},
		{"Account Linking", ActionLinkFailed, "Link Failed"},
		{"Account Linking", ActionMappingReset, "Mapping Deleted"},
		{"Account Linking", ActionMappingResetAll, "All Mappings Deleted"},

		{"Identity Providers", ActionIDPCreate, "Provider Created"},
		{"Identity Providers", ActionIDPUpdate, "Provider Updated"},
		{"Identity Providers", ActionIDPDelete, "Provider Deleted"},
		{"Identity Providers", ActionIDPToggle, "Provider Enabled/Disabled"},
		{"Identity Providers", ActionIDPTestConnection, "Connection Test"},

		{"MFA Providers", ActionMFACreate, "MFA Provider Created"},
		{"MFA Providers", ActionMFAUpdate, "MFA Provider Updated"},
		{"MFA Providers", ActionMFADelete, "MFA Provider Deleted"},
		{"MFA Providers", ActionMFAToggle, "MFA Provider Enabled/Disabled"},

		{"Administration", ActionAdminGroupAdd, "Admin Group Added"},
		{"Administration", ActionAdminGroupDelete, "Admin Group Removed"},
		{"Administration", ActionSMTPUpdate, "SMTP Updated"},
		{"Administration", ActionSMTPTest, "Test Email Sent"},
		{"Administration", ActionEmailTemplateUpdate, "Email Template Updated"},
		{"Administration", ActionEmailTemplateReset, "Email Template Reset"},

		{"Scheduled Jobs", ActionExpirationNotification, "Expiration Notice Sent"},
		{"Scheduled Jobs", ActionExpiredNotification, "Expired Notice Sent"},
		{"Scheduled Jobs", ActionExpirationConfigUpdate, "Expiration Config Changed"},
		{"Scheduled Jobs", ActionReportSent, "Report Sent"},
		{"Scheduled Jobs", ActionReportConfigUpdate, "Report Config Changed"},
	}
}
