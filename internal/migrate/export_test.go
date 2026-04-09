package migrate

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/hanej/passport/internal/crypto"
	"github.com/hanej/passport/internal/db"
)

// openTestDB creates an in-memory SQLite database with all migrations applied.
func openTestDB(t *testing.T) *db.DB {
	t.Helper()
	database, err := db.OpenMemory()
	if err != nil {
		t.Fatalf("opening memory db: %v", err)
	}
	if err := database.Migrate(context.Background()); err != nil {
		t.Fatalf("running migrations: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	return database
}

// newCrypto creates a crypto service for testing.
func newCrypto(t *testing.T) *crypto.Service {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	svc, err := crypto.NewService(key, 1)
	if err != nil {
		t.Fatalf("creating crypto service: %v", err)
	}
	return svc
}

// seedIDP inserts an IDP with a config and encrypted secrets into the store.
func seedIDP(t *testing.T, store db.Store, cryptoSvc *crypto.Service, id, name string) {
	t.Helper()
	secretJSON := []byte(`{"password":"secret123"}`)
	blob, err := cryptoSvc.Encrypt(secretJSON)
	if err != nil {
		t.Fatalf("encrypting IDP secrets: %v", err)
	}
	if err := store.CreateIDP(context.Background(), &db.IdentityProviderRecord{
		ID:           id,
		FriendlyName: name,
		Description:  "test IDP",
		ProviderType: "ad",
		Enabled:      true,
		LogoURL:      "https://example.com/logo.png",
		ConfigJSON:   `{"host":"ldap.example.com","port":389}`,
		SecretBlob:   blob,
	}); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}
}

// seedMFAProvider inserts an MFA provider with encrypted secrets into the store.
func seedMFAProvider(t *testing.T, store db.Store, cryptoSvc *crypto.Service, id, name string) {
	t.Helper()
	secretJSON := []byte(`{"secret_key":"mfasecret"}`)
	blob, err := cryptoSvc.Encrypt(secretJSON)
	if err != nil {
		t.Fatalf("encrypting MFA secrets: %v", err)
	}
	if err := store.CreateMFAProvider(context.Background(), &db.MFAProviderRecord{
		ID:           id,
		Name:         name,
		ProviderType: "email",
		Enabled:      true,
		ConfigJSON:   `{"from":"mfa@example.com"}`,
		SecretBlob:   blob,
	}); err != nil {
		t.Fatalf("creating MFA provider: %v", err)
	}
}

// seedSMTP inserts an SMTP config with encrypted secrets.
func seedSMTP(t *testing.T, store db.Store, cryptoSvc *crypto.Service) {
	t.Helper()
	secretJSON := []byte(`{"password":"smtppass"}`)
	blob, err := cryptoSvc.Encrypt(secretJSON)
	if err != nil {
		t.Fatalf("encrypting SMTP secrets: %v", err)
	}
	if err := store.SaveSMTPConfig(context.Background(), &db.SMTPConfig{
		ConfigJSON: `{"host":"smtp.example.com","port":587}`,
		SecretBlob: blob,
	}); err != nil {
		t.Fatalf("saving SMTP config: %v", err)
	}
}

// --- BuildExport ---

func TestBuildExport_Empty(t *testing.T) {
	store := openTestDB(t)
	cryptoSvc := newCrypto(t)

	data, err := BuildExport(context.Background(), store, cryptoSvc)
	if err != nil {
		t.Fatalf("BuildExport: %v", err)
	}

	if data.Version != 1 {
		t.Errorf("expected version 1, got %d", data.Version)
	}
	if data.SecretsEncrypted {
		t.Error("export should have SecretsEncrypted=false")
	}
	if data.ExportedAt == "" {
		t.Error("ExportedAt should be set")
	}
	if len(data.LocalAdmins) != 0 {
		t.Errorf("expected 0 local admins, got %d", len(data.LocalAdmins))
	}
	if len(data.IdentityProviders) != 0 {
		t.Errorf("expected 0 IDPs, got %d", len(data.IdentityProviders))
	}
	if len(data.MFAProviders) != 0 {
		t.Errorf("expected 0 MFA providers, got %d", len(data.MFAProviders))
	}
	if data.SMTPConfig != nil {
		t.Error("expected nil SMTP config")
	}
}

func TestBuildExport_IDPSecretsDecrypted(t *testing.T) {
	store := openTestDB(t)
	cryptoSvc := newCrypto(t)

	seedIDP(t, store, cryptoSvc, "idp-1", "Test IDP")

	data, err := BuildExport(context.Background(), store, cryptoSvc)
	if err != nil {
		t.Fatalf("BuildExport: %v", err)
	}

	if len(data.IdentityProviders) != 1 {
		t.Fatalf("expected 1 IDP, got %d", len(data.IdentityProviders))
	}

	ei := data.IdentityProviders[0]
	if ei.ID != "idp-1" {
		t.Errorf("expected IDP ID idp-1, got %s", ei.ID)
	}

	// Secrets should be plaintext JSON (not base64)
	var secrets map[string]string
	if err := json.Unmarshal(ei.Secrets, &secrets); err != nil {
		t.Fatalf("unmarshaling IDP secrets: %v", err)
	}
	if secrets["password"] != "secret123" {
		t.Errorf("expected password secret123, got %s", secrets["password"])
	}
}

func TestBuildExport_SMTPSecretsDecrypted(t *testing.T) {
	store := openTestDB(t)
	cryptoSvc := newCrypto(t)

	seedSMTP(t, store, cryptoSvc)

	data, err := BuildExport(context.Background(), store, cryptoSvc)
	if err != nil {
		t.Fatalf("BuildExport: %v", err)
	}

	if data.SMTPConfig == nil {
		t.Fatal("expected SMTP config to be set")
	}

	var secrets map[string]string
	if err := json.Unmarshal(data.SMTPConfig.Secrets, &secrets); err != nil {
		t.Fatalf("unmarshaling SMTP secrets: %v", err)
	}
	if secrets["password"] != "smtppass" {
		t.Errorf("expected smtppass, got %s", secrets["password"])
	}
}

func TestBuildExport_MFASecretsDecrypted(t *testing.T) {
	store := openTestDB(t)
	cryptoSvc := newCrypto(t)

	seedMFAProvider(t, store, cryptoSvc, "mfa-1", "Email MFA")

	data, err := BuildExport(context.Background(), store, cryptoSvc)
	if err != nil {
		t.Fatalf("BuildExport: %v", err)
	}

	if len(data.MFAProviders) != 1 {
		t.Fatalf("expected 1 MFA provider, got %d", len(data.MFAProviders))
	}

	var secrets map[string]string
	if err := json.Unmarshal(data.MFAProviders[0].Secrets, &secrets); err != nil {
		t.Fatalf("unmarshaling MFA secrets: %v", err)
	}
	if secrets["secret_key"] != "mfasecret" {
		t.Errorf("expected mfasecret, got %s", secrets["secret_key"])
	}
}

func TestBuildExport_AllSections(t *testing.T) {
	store := openTestDB(t)
	cryptoSvc := newCrypto(t)

	ctx := context.Background()

	// Seed local admin
	if _, err := store.CreateLocalAdmin(ctx, "admin", "hash123"); err != nil {
		t.Fatalf("creating admin: %v", err)
	}

	// Seed IDP with related data
	seedIDP(t, store, cryptoSvc, "idp-1", "LDAP")
	if err := store.SetAttributeMappings(ctx, "idp-1", []db.AttributeMapping{
		{IDPID: "idp-1", CanonicalName: "email", DirectoryAttr: "mail"},
	}); err != nil {
		t.Fatalf("setting attribute mappings: %v", err)
	}
	if err := store.SetCorrelationRule(ctx, &db.CorrelationRule{
		IDPID: "idp-1", SourceCanonicalAttr: "email", TargetDirectoryAttr: "userPrincipalName", MatchMode: "exact",
	}); err != nil {
		t.Fatalf("setting correlation rule: %v", err)
	}
	if err := store.SaveExpirationConfig(ctx, &db.ExpirationConfig{
		IDPID: "idp-1", Enabled: true, CronSchedule: "0 8 * * *", DaysBeforeExpiration: 14,
	}); err != nil {
		t.Fatalf("saving expiration config: %v", err)
	}
	if err := store.SaveExpirationFilters(ctx, "idp-1", []db.ExpirationFilter{
		{IDPID: "idp-1", Attribute: "department", Pattern: "IT", Description: "IT dept"},
	}); err != nil {
		t.Fatalf("saving expiration filters: %v", err)
	}

	// Seed admin group
	if err := store.CreateAdminGroup(ctx, &db.AdminGroup{IDPID: "idp-1", GroupDN: "cn=admins,dc=example,dc=com", Description: "admins"}); err != nil {
		t.Fatalf("creating admin group: %v", err)
	}

	// Seed user mapping
	linkedAt := time.Now().UTC().Truncate(time.Second)
	if err := store.UpsertMapping(ctx, &db.UserIDPMapping{
		AuthProviderID: "idp-1", AuthUsername: "alice", TargetIDPID: "idp-1",
		TargetAccountDN: "cn=alice,dc=example,dc=com", LinkType: "manual", LinkedAt: linkedAt,
	}); err != nil {
		t.Fatalf("upserting mapping: %v", err)
	}

	// Seed SMTP
	seedSMTP(t, store, cryptoSvc)

	// Seed MFA
	seedMFAProvider(t, store, cryptoSvc, "mfa-1", "Email MFA")

	// Seed branding
	if err := store.SaveBrandingConfig(ctx, &db.BrandingConfig{
		AppTitle: "MyApp", AppAbbreviation: "MA", PrimaryColor: "#123456",
	}); err != nil {
		t.Fatalf("saving branding: %v", err)
	}

	// Seed email template
	if err := store.SaveEmailTemplate(ctx, &db.EmailTemplate{
		TemplateType: "password_reset", Subject: "Reset your password", BodyHTML: "<p>Click here</p>",
	}); err != nil {
		t.Fatalf("saving email template: %v", err)
	}

	data, err := BuildExport(ctx, store, cryptoSvc)
	if err != nil {
		t.Fatalf("BuildExport: %v", err)
	}

	// Verify each section
	if len(data.LocalAdmins) != 1 {
		t.Errorf("expected 1 local admin, got %d", len(data.LocalAdmins))
	}
	if data.LocalAdmins[0].Username != "admin" {
		t.Errorf("expected admin, got %s", data.LocalAdmins[0].Username)
	}

	if len(data.IdentityProviders) != 1 {
		t.Fatalf("expected 1 IDP, got %d", len(data.IdentityProviders))
	}
	ei := data.IdentityProviders[0]
	if len(ei.AttributeMappings) != 1 || ei.AttributeMappings[0].CanonicalName != "email" {
		t.Errorf("attribute mappings not exported: %+v", ei.AttributeMappings)
	}
	if ei.CorrelationRule == nil || ei.CorrelationRule.MatchMode != "exact" {
		t.Errorf("correlation rule not exported: %+v", ei.CorrelationRule)
	}
	if ei.ExpirationConfig == nil || ei.ExpirationConfig.DaysBeforeExpiration != 14 {
		t.Errorf("expiration config not exported: %+v", ei.ExpirationConfig)
	}
	if len(ei.ExpirationFilters) != 1 || ei.ExpirationFilters[0].Pattern != "IT" {
		t.Errorf("expiration filters not exported: %+v", ei.ExpirationFilters)
	}

	if len(data.AdminGroups) != 1 {
		t.Errorf("expected 1 admin group, got %d", len(data.AdminGroups))
	}
	if len(data.UserMappings) != 1 {
		t.Errorf("expected 1 user mapping, got %d", len(data.UserMappings))
	}
	if data.SMTPConfig == nil {
		t.Error("expected SMTP config")
	}
	if len(data.MFAProviders) != 1 {
		t.Errorf("expected 1 MFA provider, got %d", len(data.MFAProviders))
	}
	if data.Branding == nil || data.Branding.AppTitle != "MyApp" {
		t.Errorf("branding not exported: %+v", data.Branding)
	}
	// There are default templates seeded by migrations; verify our saved one is present.
	var foundTemplate bool
	for _, tpl := range data.EmailTemplates {
		if tpl.TemplateType == "password_reset" && tpl.Subject == "Reset your password" {
			foundTemplate = true
			break
		}
	}
	if !foundTemplate {
		t.Errorf("password_reset template not found in export: %+v", data.EmailTemplates)
	}
}

// --- BuildBackup ---

func TestBuildBackup_SecretsAreBase64(t *testing.T) {
	store := openTestDB(t)
	cryptoSvc := newCrypto(t)

	seedIDP(t, store, cryptoSvc, "idp-1", "LDAP")
	seedMFAProvider(t, store, cryptoSvc, "mfa-1", "Email MFA")
	seedSMTP(t, store, cryptoSvc)

	data, err := BuildBackup(context.Background(), store)
	if err != nil {
		t.Fatalf("BuildBackup: %v", err)
	}

	if !data.SecretsEncrypted {
		t.Error("backup should have SecretsEncrypted=true")
	}

	// IDP secrets should be a base64 JSON string, not a JSON object
	var idpSecretStr string
	if err := json.Unmarshal(data.IdentityProviders[0].Secrets, &idpSecretStr); err != nil {
		t.Fatalf("IDP secrets should be a base64 string, got: %s", data.IdentityProviders[0].Secrets)
	}
	if idpSecretStr == "" {
		t.Error("IDP base64 secret should not be empty")
	}

	// MFA secrets should be a base64 JSON string
	var mfaSecretStr string
	if err := json.Unmarshal(data.MFAProviders[0].Secrets, &mfaSecretStr); err != nil {
		t.Fatalf("MFA secrets should be a base64 string, got: %s", data.MFAProviders[0].Secrets)
	}

	// SMTP secrets should be a base64 JSON string
	var smtpSecretStr string
	if err := json.Unmarshal(data.SMTPConfig.Secrets, &smtpSecretStr); err != nil {
		t.Fatalf("SMTP secrets should be a base64 string, got: %s", data.SMTPConfig.Secrets)
	}
}

// --- RunImport ---

func TestRunImport_AllSections(t *testing.T) {
	store := openTestDB(t)
	cryptoSvc := newCrypto(t)

	ctx := context.Background()
	secretsJSON := json.RawMessage(`{"password":"secret123"}`)

	data := &ExportData{
		Version:          1,
		ExportedAt:       time.Now().UTC().Format(time.RFC3339),
		SecretsEncrypted: false,
		LocalAdmins: []ExportLocalAdmin{
			{Username: "alice", PasswordHash: "hash-alice", MustChangePassword: false},
			{Username: "bob", PasswordHash: "hash-bob", MustChangePassword: true},
		},
		IdentityProviders: []ExportIDP{
			{
				ID: "idp-1", FriendlyName: "LDAP", Description: "test", ProviderType: "ad",
				Enabled: true, LogoURL: "https://example.com/logo.png",
				Config:  json.RawMessage(`{"host":"ldap.example.com"}`),
				Secrets: secretsJSON,
				AttributeMappings: []ExportAttrMapping{
					{CanonicalName: "email", DirectoryAttr: "mail"},
				},
				CorrelationRule: &ExportCorrelationRule{
					SourceCanonicalAttr: "email", TargetDirectoryAttr: "userPrincipalName", MatchMode: "exact",
				},
				ExpirationConfig: &ExportExpirationConfig{
					Enabled: true, CronSchedule: "0 8 * * *", DaysBeforeExpiration: 14,
				},
				ExpirationFilters: []ExportExpirationFilter{
					{Attribute: "department", Pattern: "IT", Description: "IT dept"},
				},
			},
		},
		AdminGroups: []ExportAdminGroup{
			{IDPID: "idp-1", GroupDN: "cn=admins,dc=example,dc=com", Description: "admins"},
		},
		UserMappings: []ExportMapping{
			{
				AuthProviderID: "idp-1", AuthUsername: "alice", TargetIDPID: "idp-1",
				TargetAccountDN: "cn=alice,dc=example,dc=com", LinkType: "manual",
				LinkedAt: time.Now().UTC().Format(time.RFC3339),
			},
		},
		SMTPConfig: &ExportSMTP{
			Config:  json.RawMessage(`{"host":"smtp.example.com","port":587}`),
			Secrets: json.RawMessage(`{"password":"smtppass"}`),
		},
		MFAProviders: []ExportMFAProvider{
			{
				ID: "mfa-1", Name: "Email MFA", ProviderType: "email", Enabled: true,
				Config:  json.RawMessage(`{"from":"mfa@example.com"}`),
				Secrets: json.RawMessage(`{"secret_key":"mfasecret"}`),
			},
		},
		Branding: &db.BrandingConfig{
			AppTitle: "MyApp", AppAbbreviation: "MA", PrimaryColor: "#123456",
		},
		EmailTemplates: []ExportEmailTemplate{
			{TemplateType: "password_reset", Subject: "Reset", BodyHTML: "<p>Reset</p>"},
			{TemplateType: "password_expiry_notice", Subject: "Expiring", BodyHTML: "<p>Expiring</p>"},
		},
	}

	result, err := RunImport(ctx, store, cryptoSvc, data, AllSections())
	if err != nil {
		t.Fatalf("RunImport: %v", err)
	}

	if len(result.Errors) > 0 {
		t.Errorf("unexpected import errors: %v", result.Errors)
	}

	// Local admins
	if result.LocalAdmins != 2 {
		t.Errorf("expected 2 local admins, got %d", result.LocalAdmins)
	}
	alice, err := store.GetLocalAdmin(ctx, "alice")
	if err != nil {
		t.Fatalf("getting alice: %v", err)
	}
	if alice.MustChangePassword {
		t.Error("alice should not have must_change_password")
	}
	bob, err := store.GetLocalAdmin(ctx, "bob")
	if err != nil {
		t.Fatalf("getting bob: %v", err)
	}
	if !bob.MustChangePassword {
		t.Error("bob should have must_change_password")
	}

	// IDPs
	if result.IDPs != 1 {
		t.Errorf("expected 1 IDP, got %d", result.IDPs)
	}
	idp, err := store.GetIDP(ctx, "idp-1")
	if err != nil {
		t.Fatalf("getting IDP: %v", err)
	}
	if idp.FriendlyName != "LDAP" {
		t.Errorf("expected LDAP, got %s", idp.FriendlyName)
	}
	if idp.LogoURL != "https://example.com/logo.png" {
		t.Errorf("expected logo URL, got %s", idp.LogoURL)
	}
	// Verify secrets were encrypted
	if len(idp.SecretBlob) == 0 {
		t.Error("IDP secret blob should be non-empty after import")
	}
	plaintext, err := cryptoSvc.Decrypt(idp.SecretBlob)
	if err != nil {
		t.Fatalf("decrypting IDP secrets: %v", err)
	}
	var idpSecrets map[string]string
	if err := json.Unmarshal(plaintext, &idpSecrets); err != nil {
		t.Fatalf("unmarshaling IDP secrets: %v", err)
	}
	if idpSecrets["password"] != "secret123" {
		t.Errorf("expected secret123, got %s", idpSecrets["password"])
	}

	// Attribute mappings
	attrMappings, err := store.ListAttributeMappings(ctx, "idp-1")
	if err != nil {
		t.Fatalf("listing attribute mappings: %v", err)
	}
	if len(attrMappings) != 1 || attrMappings[0].CanonicalName != "email" {
		t.Errorf("unexpected attribute mappings: %+v", attrMappings)
	}

	// Correlation rule
	rule, err := store.GetCorrelationRule(ctx, "idp-1")
	if err != nil {
		t.Fatalf("getting correlation rule: %v", err)
	}
	if rule == nil || rule.MatchMode != "exact" {
		t.Errorf("unexpected correlation rule: %+v", rule)
	}

	// Expiration config
	expCfg, err := store.GetExpirationConfig(ctx, "idp-1")
	if err != nil {
		t.Fatalf("getting expiration config: %v", err)
	}
	if expCfg == nil || expCfg.DaysBeforeExpiration != 14 {
		t.Errorf("unexpected expiration config: %+v", expCfg)
	}

	// Expiration filters
	expFilters, err := store.ListExpirationFilters(ctx, "idp-1")
	if err != nil {
		t.Fatalf("listing expiration filters: %v", err)
	}
	if len(expFilters) != 1 || expFilters[0].Pattern != "IT" {
		t.Errorf("unexpected expiration filters: %+v", expFilters)
	}

	// Admin groups
	if result.AdminGroups != 1 {
		t.Errorf("expected 1 admin group, got %d", result.AdminGroups)
	}

	// User mappings
	if result.UserMappings != 1 {
		t.Errorf("expected 1 user mapping, got %d", result.UserMappings)
	}

	// SMTP
	if !result.SMTP {
		t.Error("expected SMTP to be imported")
	}
	smtpCfg, err := store.GetSMTPConfig(ctx)
	if err != nil {
		t.Fatalf("getting SMTP config: %v", err)
	}
	if smtpCfg == nil {
		t.Fatal("SMTP config should exist")
	}
	smtpPlain, err := cryptoSvc.Decrypt(smtpCfg.SecretBlob)
	if err != nil {
		t.Fatalf("decrypting SMTP secrets: %v", err)
	}
	var smtpSecrets map[string]string
	if err := json.Unmarshal(smtpPlain, &smtpSecrets); err != nil {
		t.Fatalf("unmarshaling SMTP secrets: %v", err)
	}
	if smtpSecrets["password"] != "smtppass" {
		t.Errorf("expected smtppass, got %s", smtpSecrets["password"])
	}

	// MFA
	if result.MFAProviders != 1 {
		t.Errorf("expected 1 MFA provider, got %d", result.MFAProviders)
	}

	// Branding
	if !result.Branding {
		t.Error("expected branding to be imported")
	}
	branding, err := store.GetBrandingConfig(ctx)
	if err != nil {
		t.Fatalf("getting branding: %v", err)
	}
	if branding.AppTitle != "MyApp" {
		t.Errorf("expected MyApp, got %s", branding.AppTitle)
	}

	// Email templates
	if result.EmailTemplates != 2 {
		t.Errorf("expected 2 email templates, got %d", result.EmailTemplates)
	}
	tpl, err := store.GetEmailTemplate(ctx, "password_reset")
	if err != nil {
		t.Fatalf("getting email template: %v", err)
	}
	if tpl.Subject != "Reset" {
		t.Errorf("expected Reset, got %s", tpl.Subject)
	}
}

func TestRunImport_PartialSections(t *testing.T) {
	store := openTestDB(t)
	cryptoSvc := newCrypto(t)

	ctx := context.Background()

	data := &ExportData{
		Version:          1,
		ExportedAt:       time.Now().UTC().Format(time.RFC3339),
		SecretsEncrypted: false,
		LocalAdmins: []ExportLocalAdmin{
			{Username: "alice", PasswordHash: "hash-alice"},
		},
		Branding: &db.BrandingConfig{AppTitle: "MyApp"},
		EmailTemplates: []ExportEmailTemplate{
			{TemplateType: "password_reset", Subject: "Reset", BodyHTML: "<p>Reset</p>"},
		},
	}

	// Only import branding and templates, skip admins
	sections := ImportSections{Branding: true, Templates: true}
	result, err := RunImport(ctx, store, cryptoSvc, data, sections)
	if err != nil {
		t.Fatalf("RunImport: %v", err)
	}

	if result.LocalAdmins != 0 {
		t.Errorf("expected 0 local admins (skipped), got %d", result.LocalAdmins)
	}
	if !result.Branding {
		t.Error("expected branding to be imported")
	}
	if result.EmailTemplates != 1 {
		t.Errorf("expected 1 email template, got %d", result.EmailTemplates)
	}

	// Verify alice was NOT imported
	if _, err := store.GetLocalAdmin(ctx, "alice"); err == nil {
		t.Error("alice should not have been imported (section disabled)")
	}
}

func TestRunImport_UpdateExisting(t *testing.T) {
	store := openTestDB(t)
	cryptoSvc := newCrypto(t)

	ctx := context.Background()

	// Pre-create admin and IDP
	if _, err := store.CreateLocalAdmin(ctx, "alice", "old-hash"); err != nil {
		t.Fatalf("creating admin: %v", err)
	}
	if err := store.CreateIDP(ctx, &db.IdentityProviderRecord{
		ID: "idp-1", FriendlyName: "Old Name", ProviderType: "ad",
		ConfigJSON: `{}`,
	}); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	data := &ExportData{
		Version:          1,
		ExportedAt:       time.Now().UTC().Format(time.RFC3339),
		SecretsEncrypted: false,
		LocalAdmins: []ExportLocalAdmin{
			{Username: "alice", PasswordHash: "new-hash", MustChangePassword: false},
		},
		IdentityProviders: []ExportIDP{
			{
				ID: "idp-1", FriendlyName: "New Name", ProviderType: "ad",
				Config:  json.RawMessage(`{}`),
				Secrets: json.RawMessage(`{}`),
			},
		},
	}

	result, err := RunImport(ctx, store, cryptoSvc, data, ImportSections{Admins: true, IDPs: true})
	if err != nil {
		t.Fatalf("RunImport: %v", err)
	}
	if len(result.Errors) > 0 {
		t.Errorf("unexpected errors: %v", result.Errors)
	}

	alice, err := store.GetLocalAdmin(ctx, "alice")
	if err != nil {
		t.Fatalf("getting alice: %v", err)
	}
	if alice.PasswordHash != "new-hash" {
		t.Errorf("expected new-hash, got %s", alice.PasswordHash)
	}

	idp, err := store.GetIDP(ctx, "idp-1")
	if err != nil {
		t.Fatalf("getting IDP: %v", err)
	}
	if idp.FriendlyName != "New Name" {
		t.Errorf("expected New Name, got %s", idp.FriendlyName)
	}
}

func TestRunImport_AdminGroupsIdempotent(t *testing.T) {
	store := openTestDB(t)
	cryptoSvc := newCrypto(t)

	ctx := context.Background()

	// Create the IDP first
	if err := store.CreateIDP(ctx, &db.IdentityProviderRecord{
		ID: "idp-1", FriendlyName: "LDAP", ProviderType: "ad", ConfigJSON: `{}`,
	}); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	data := &ExportData{
		Version:          1,
		ExportedAt:       time.Now().UTC().Format(time.RFC3339),
		SecretsEncrypted: false,
		AdminGroups: []ExportAdminGroup{
			{IDPID: "idp-1", GroupDN: "cn=admins,dc=example,dc=com", Description: "admins"},
		},
	}

	sections := ImportSections{Groups: true}

	// Import twice
	result1, err := RunImport(ctx, store, cryptoSvc, data, sections)
	if err != nil {
		t.Fatalf("first import: %v", err)
	}
	if result1.AdminGroups != 1 {
		t.Errorf("expected 1 admin group after first import, got %d", result1.AdminGroups)
	}

	result2, err := RunImport(ctx, store, cryptoSvc, data, sections)
	if err != nil {
		t.Fatalf("second import: %v", err)
	}
	if len(result2.Errors) > 0 {
		t.Errorf("unexpected errors on second import: %v", result2.Errors)
	}
	if result2.AdminGroups != 1 {
		t.Errorf("expected 1 admin group after second import, got %d", result2.AdminGroups)
	}

	// Verify exactly 1 group exists (no duplicates)
	groups, err := store.GetAdminGroupsByIDP(ctx, "idp-1")
	if err != nil {
		t.Fatalf("listing admin groups: %v", err)
	}
	if len(groups) != 1 {
		t.Errorf("expected 1 admin group in DB, got %d (duplicate created)", len(groups))
	}
}

func TestRunImport_UnsupportedVersion(t *testing.T) {
	store := openTestDB(t)
	cryptoSvc := newCrypto(t)

	data := &ExportData{Version: 99}
	_, err := RunImport(context.Background(), store, cryptoSvc, data, AllSections())
	if err == nil {
		t.Error("expected error for unsupported version")
	}
}

func TestRunImport_DefaultMFAProviderID(t *testing.T) {
	store := openTestDB(t)
	cryptoSvc := newCrypto(t)

	ctx := context.Background()

	// First create the MFA provider
	if err := store.CreateMFAProvider(ctx, &db.MFAProviderRecord{
		ID: "mfa-1", Name: "Email", ProviderType: "email", ConfigJSON: `{}`,
	}); err != nil {
		t.Fatalf("creating MFA provider: %v", err)
	}

	mfaID := "mfa-1"
	data := &ExportData{
		Version:              1,
		ExportedAt:           time.Now().UTC().Format(time.RFC3339),
		SecretsEncrypted:     false,
		DefaultMFAProviderID: &mfaID,
	}

	result, err := RunImport(ctx, store, cryptoSvc, data, ImportSections{MFA: true})
	if err != nil {
		t.Fatalf("RunImport: %v", err)
	}
	if len(result.Errors) > 0 {
		t.Errorf("unexpected errors: %v", result.Errors)
	}

	defaultID, err := store.GetDefaultMFAProviderID(ctx)
	if err != nil {
		t.Fatalf("getting default MFA provider ID: %v", err)
	}
	if defaultID == nil || *defaultID != "mfa-1" {
		t.Errorf("expected default MFA provider mfa-1, got %v", defaultID)
	}
}

// --- Round-trip tests ---

func TestRoundTrip_ExportThenImport(t *testing.T) {
	srcStore := openTestDB(t)
	dstStore := openTestDB(t)
	cryptoSvc := newCrypto(t)

	ctx := context.Background()

	// Seed source
	if _, err := srcStore.CreateLocalAdmin(ctx, "admin", "hash-admin"); err != nil {
		t.Fatalf("creating admin: %v", err)
	}
	seedIDP(t, srcStore, cryptoSvc, "idp-1", "LDAP")
	seedSMTP(t, srcStore, cryptoSvc)
	seedMFAProvider(t, srcStore, cryptoSvc, "mfa-1", "Email MFA")
	if err := srcStore.SaveBrandingConfig(ctx, &db.BrandingConfig{AppTitle: "MyApp"}); err != nil {
		t.Fatalf("saving branding: %v", err)
	}
	if err := srcStore.SaveEmailTemplate(ctx, &db.EmailTemplate{
		TemplateType: "password_reset", Subject: "Reset", BodyHTML: "<p>Reset</p>",
	}); err != nil {
		t.Fatalf("saving template: %v", err)
	}

	// Export
	exportData, err := BuildExport(ctx, srcStore, cryptoSvc)
	if err != nil {
		t.Fatalf("BuildExport: %v", err)
	}

	// Import into destination
	result, err := RunImport(ctx, dstStore, cryptoSvc, exportData, AllSections())
	if err != nil {
		t.Fatalf("RunImport: %v", err)
	}
	if len(result.Errors) > 0 {
		t.Errorf("import errors: %v", result.Errors)
	}

	// Verify destination
	admins, err := dstStore.ListLocalAdmins(ctx)
	if err != nil {
		t.Fatalf("listing admins: %v", err)
	}
	if len(admins) != 1 || admins[0].Username != "admin" {
		t.Errorf("unexpected admins: %+v", admins)
	}

	idp, err := dstStore.GetIDP(ctx, "idp-1")
	if err != nil {
		t.Fatalf("getting IDP: %v", err)
	}
	// Verify IDP secret was preserved through export → import
	plaintext, err := cryptoSvc.Decrypt(idp.SecretBlob)
	if err != nil {
		t.Fatalf("decrypting IDP secret: %v", err)
	}
	var secrets map[string]string
	if err := json.Unmarshal(plaintext, &secrets); err != nil {
		t.Fatalf("unmarshaling secrets: %v", err)
	}
	if secrets["password"] != "secret123" {
		t.Errorf("secret not preserved: got %s", secrets["password"])
	}

	branding, err := dstStore.GetBrandingConfig(ctx)
	if err != nil {
		t.Fatalf("getting branding: %v", err)
	}
	if branding.AppTitle != "MyApp" {
		t.Errorf("branding not preserved: got %s", branding.AppTitle)
	}

	tplImported, err := dstStore.GetEmailTemplate(ctx, "password_reset")
	if err != nil {
		t.Fatalf("getting password_reset template: %v", err)
	}
	if tplImported.Subject != "Reset" {
		t.Errorf("template subject not preserved: got %s", tplImported.Subject)
	}
}

func TestRoundTrip_BackupThenImport(t *testing.T) {
	srcStore := openTestDB(t)
	dstStore := openTestDB(t)
	cryptoSvc := newCrypto(t)

	ctx := context.Background()

	seedIDP(t, srcStore, cryptoSvc, "idp-1", "LDAP")
	seedMFAProvider(t, srcStore, cryptoSvc, "mfa-1", "Email MFA")
	seedSMTP(t, srcStore, cryptoSvc)

	backup, err := BuildBackup(ctx, srcStore)
	if err != nil {
		t.Fatalf("BuildBackup: %v", err)
	}

	result, err := RunImport(ctx, dstStore, cryptoSvc, backup, AllSections())
	if err != nil {
		t.Fatalf("RunImport: %v", err)
	}
	if len(result.Errors) > 0 {
		t.Errorf("import errors: %v", result.Errors)
	}

	// Verify IDP secret blob was preserved exactly (backup uses same encrypted blob)
	srcIDPs, _ := srcStore.ListIDPs(ctx)
	dstIDP, err := dstStore.GetIDP(ctx, "idp-1")
	if err != nil {
		t.Fatalf("getting IDP from dst: %v", err)
	}

	// Both should decrypt to the same plaintext
	srcPlain, err := cryptoSvc.Decrypt(srcIDPs[0].SecretBlob)
	if err != nil {
		t.Fatalf("decrypting src: %v", err)
	}
	dstPlain, err := cryptoSvc.Decrypt(dstIDP.SecretBlob)
	if err != nil {
		t.Fatalf("decrypting dst: %v", err)
	}
	if string(srcPlain) != string(dstPlain) {
		t.Errorf("secrets differ: src=%s dst=%s", srcPlain, dstPlain)
	}
}

// --- Additional RunImport error paths ---

func TestRunImport_MalformedLinkedAt(t *testing.T) {
	store := openTestDB(t)
	cryptoSvc := newCrypto(t)

	// Create the IDP so the mapping insert at least reaches the time-parse step.
	if err := store.CreateIDP(context.Background(), &db.IdentityProviderRecord{
		ID: "idp-1", FriendlyName: "LDAP", ProviderType: "ad", ConfigJSON: `{}`,
	}); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	data := &ExportData{
		Version:          1,
		ExportedAt:       time.Now().UTC().Format(time.RFC3339),
		SecretsEncrypted: false,
		UserMappings: []ExportMapping{
			{
				AuthProviderID:  "idp-1",
				AuthUsername:    "alice",
				TargetIDPID:     "idp-1",
				TargetAccountDN: "cn=alice,dc=example,dc=com",
				LinkType:        "manual",
				LinkedAt:        "not-a-date", // malformed
			},
		},
	}

	result, err := RunImport(context.Background(), store, cryptoSvc, data, ImportSections{Mappings: true})
	if err != nil {
		t.Fatalf("RunImport returned unexpected hard error: %v", err)
	}
	// The malformed date should produce a per-record error, not a hard failure.
	if len(result.Errors) == 0 {
		t.Error("expected at least one error for malformed linked_at date")
	}
	if result.UserMappings != 0 {
		t.Errorf("expected 0 imported mappings, got %d", result.UserMappings)
	}
}

func TestRunImport_MalformedVerifiedAt(t *testing.T) {
	store := openTestDB(t)
	cryptoSvc := newCrypto(t)

	if err := store.CreateIDP(context.Background(), &db.IdentityProviderRecord{
		ID: "idp-1", FriendlyName: "LDAP", ProviderType: "ad", ConfigJSON: `{}`,
	}); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	badVerified := "not-a-date"
	data := &ExportData{
		Version:          1,
		ExportedAt:       time.Now().UTC().Format(time.RFC3339),
		SecretsEncrypted: false,
		UserMappings: []ExportMapping{
			{
				AuthProviderID:  "idp-1",
				AuthUsername:    "alice",
				TargetIDPID:     "idp-1",
				TargetAccountDN: "cn=alice,dc=example,dc=com",
				LinkType:        "manual",
				LinkedAt:        time.Now().UTC().Format(time.RFC3339),
				VerifiedAt:      &badVerified, // malformed
			},
		},
	}

	result, err := RunImport(context.Background(), store, cryptoSvc, data, ImportSections{Mappings: true})
	if err != nil {
		t.Fatalf("RunImport returned unexpected hard error: %v", err)
	}
	if len(result.Errors) == 0 {
		t.Error("expected at least one error for malformed verified_at date")
	}
}

func TestRunImport_EncryptedSecretsInvalidBase64(t *testing.T) {
	store := openTestDB(t)
	cryptoSvc := newCrypto(t)

	// SecretsEncrypted=true but the value is not valid base64 inside the JSON string.
	data := &ExportData{
		Version:          1,
		ExportedAt:       time.Now().UTC().Format(time.RFC3339),
		SecretsEncrypted: true,
		IdentityProviders: []ExportIDP{
			{
				ID:           "idp-1",
				FriendlyName: "LDAP",
				ProviderType: "ad",
				Config:       json.RawMessage(`{}`),
				// Valid JSON string but invalid base64 content.
				Secrets: json.RawMessage(`"!!!not-valid-base64!!!"`),
			},
		},
	}

	result, err := RunImport(context.Background(), store, cryptoSvc, data, ImportSections{IDPs: true})
	if err != nil {
		t.Fatalf("RunImport returned unexpected hard error: %v", err)
	}
	if len(result.Errors) == 0 {
		t.Error("expected at least one error for invalid base64 secret")
	}
	if result.IDPs != 0 {
		t.Errorf("expected 0 imported IDPs, got %d", result.IDPs)
	}
}

// --- Additional resolveSecretBlob error paths ---

func TestResolveSecretBlob_EncryptedInvalidJSON(t *testing.T) {
	cryptoSvc := newCrypto(t)

	// encrypted=true but secrets is not a JSON string (it's a JSON object).
	secrets := json.RawMessage(`{"key":"value"}`)

	_, err := resolveSecretBlob(true, secrets, cryptoSvc)
	if err == nil {
		t.Error("expected error for non-string JSON in encrypted mode")
	}
}

func TestResolveSecretBlob_EncryptedInvalidBase64(t *testing.T) {
	cryptoSvc := newCrypto(t)

	// encrypted=true, JSON is a valid string, but content is not valid base64.
	secrets := json.RawMessage(`"this is !!! not base64 !!!"`)

	_, err := resolveSecretBlob(true, secrets, cryptoSvc)
	if err == nil {
		t.Error("expected error for invalid base64 in encrypted mode")
	}
}

func TestResolveSecretBlob_Empty(t *testing.T) {
	cryptoSvc := newCrypto(t)

	tests := []struct {
		name    string
		secrets json.RawMessage
	}{
		{"nil", nil},
		{"empty", json.RawMessage{}},
		{"empty object", json.RawMessage(`{}`)},
		{"quoted empty object", json.RawMessage(`"{}"`)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blob, err := resolveSecretBlob(false, tt.secrets, cryptoSvc)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if blob != nil {
				t.Errorf("expected nil blob, got %v", blob)
			}
		})
	}
}

func TestResolveSecretBlob_Plaintext(t *testing.T) {
	cryptoSvc := newCrypto(t)
	secrets := json.RawMessage(`{"password":"test"}`)

	blob, err := resolveSecretBlob(false, secrets, cryptoSvc)
	if err != nil {
		t.Fatalf("resolveSecretBlob: %v", err)
	}
	if len(blob) == 0 {
		t.Fatal("expected non-empty blob")
	}

	// Verify it decrypts back to the original
	plaintext, err := cryptoSvc.Decrypt(blob)
	if err != nil {
		t.Fatalf("decrypting: %v", err)
	}
	if string(plaintext) != `{"password":"test"}` {
		t.Errorf("unexpected plaintext: %s", plaintext)
	}
}

func TestResolveSecretBlob_Encrypted(t *testing.T) {
	cryptoSvc := newCrypto(t)

	// Simulate what BuildBackup does: encrypt then base64 encode
	originalBlob, err := cryptoSvc.Encrypt([]byte(`{"password":"test"}`))
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}

	// Create the base64-encoded JSON string that BuildBackup produces
	b64secret := json.RawMessage(`"` + base64.StdEncoding.EncodeToString(originalBlob) + `"`)

	blob, err := resolveSecretBlob(true, b64secret, cryptoSvc)
	if err != nil {
		t.Fatalf("resolveSecretBlob: %v", err)
	}

	// The returned blob should be the original encrypted blob
	if string(blob) != string(originalBlob) {
		t.Error("decrypted blob does not match original")
	}
}

// TestBuildExport_WithVerifiedAt exercises the m.VerifiedAt != nil branch in buildCommon.
func TestBuildExport_WithVerifiedAt(t *testing.T) {
	store := openTestDB(t)
	cryptoSvc := newCrypto(t)
	ctx := context.Background()

	seedIDP(t, store, cryptoSvc, "idp-1", "LDAP")

	verifiedAt := time.Now().UTC().Truncate(time.Second)
	linkedAt := time.Now().UTC().Truncate(time.Second)
	if err := store.UpsertMapping(ctx, &db.UserIDPMapping{
		AuthProviderID:  "idp-1",
		AuthUsername:    "alice",
		TargetIDPID:     "idp-1",
		TargetAccountDN: "cn=alice,dc=example,dc=com",
		LinkType:        "manual",
		LinkedAt:        linkedAt,
		VerifiedAt:      &verifiedAt,
	}); err != nil {
		t.Fatalf("upserting mapping with VerifiedAt: %v", err)
	}

	data, err := BuildExport(ctx, store, cryptoSvc)
	if err != nil {
		t.Fatalf("BuildExport: %v", err)
	}
	if len(data.UserMappings) != 1 {
		t.Fatalf("expected 1 mapping, got %d", len(data.UserMappings))
	}
	if data.UserMappings[0].VerifiedAt == nil {
		t.Error("expected VerifiedAt to be set in export")
	}
}

// TestBuildExport_DecryptIDPError exercises the crypto decrypt error path for IDP secrets.
func TestBuildExport_DecryptIDPError(t *testing.T) {
	store := openTestDB(t)
	cryptoSvc1 := newCrypto(t) // used to encrypt secrets
	cryptoSvc2 := newCrypto(t) // different key — will fail to decrypt
	ctx := context.Background()

	// Seed IDP encrypted with cryptoSvc1.
	seedIDP(t, store, cryptoSvc1, "idp-1", "LDAP")

	// Try to export with cryptoSvc2 — should fail on decrypt.
	_, err := BuildExport(ctx, store, cryptoSvc2)
	if err == nil {
		t.Error("expected decrypt error when exporting with wrong key")
	}
}

// TestBuildExport_DecryptSMTPError exercises the SMTP decode error path.
func TestBuildExport_DecryptSMTPError(t *testing.T) {
	store := openTestDB(t)
	cryptoSvc1 := newCrypto(t)
	cryptoSvc2 := newCrypto(t)
	ctx := context.Background()

	// Seed SMTP with cryptoSvc1.
	seedSMTP(t, store, cryptoSvc1)

	// Export with cryptoSvc2 — should fail on SMTP decrypt.
	_, err := BuildExport(ctx, store, cryptoSvc2)
	if err == nil {
		t.Error("expected decrypt error for SMTP with wrong key")
	}
}

// TestBuildExport_MFAWithEmptySecretBlob exercises the skip when MFA SecretBlob is empty.
func TestBuildExport_MFAWithEmptySecretBlob(t *testing.T) {
	store := openTestDB(t)
	cryptoSvc := newCrypto(t)
	ctx := context.Background()

	// Seed MFA provider without secrets (empty SecretBlob).
	if err := store.CreateMFAProvider(ctx, &db.MFAProviderRecord{
		ID:           "mfa-no-secrets",
		Name:         "Email MFA",
		ProviderType: "email",
		Enabled:      true,
		ConfigJSON:   `{"from":"mfa@example.com"}`,
		SecretBlob:   nil,
	}); err != nil {
		t.Fatalf("creating MFA provider: %v", err)
	}

	data, err := BuildExport(ctx, store, cryptoSvc)
	if err != nil {
		t.Fatalf("BuildExport: %v", err)
	}
	if len(data.MFAProviders) != 1 {
		t.Fatalf("expected 1 MFA provider, got %d", len(data.MFAProviders))
	}
}

// TestBuildExport_ListIDPsError covers the error path when the second ListIDPs call
// (inside BuildExport, after buildCommon) fails.
func TestBuildExport_ListIDPsError(t *testing.T) {
	database := openTestDB(t)
	store := &mockMigrateStore{
		DB:               database,
		listIDPsErr:      fmt.Errorf("list IDPs failed"),
		listIDPsErrAfter: 1, // call #1 (inside buildCommon) succeeds; call #2 fails
	}
	cryptoSvc := newCrypto(t)

	_, err := BuildExport(context.Background(), store, cryptoSvc)
	if err == nil {
		t.Error("expected error when second ListIDPs call fails in BuildExport")
	}
}

// TestBuildExport_ListMFAProvidersError covers the error path when the second
// ListMFAProviders call (inside BuildExport, after buildCommon) fails.
func TestBuildExport_ListMFAProvidersError(t *testing.T) {
	database := openTestDB(t)
	store := &mockMigrateStore{
		DB:                       database,
		listMFAProvidersErr:      fmt.Errorf("list MFA providers failed"),
		listMFAProvidersErrAfter: 1, // call #1 (inside buildCommon) succeeds; call #2 fails
	}
	cryptoSvc := newCrypto(t)

	_, err := BuildExport(context.Background(), store, cryptoSvc)
	if err == nil {
		t.Error("expected error when second ListMFAProviders call fails in BuildExport")
	}
}

// TestRunImport_WithVerifiedAt exercises the VerifiedAt success branch.
func TestRunImport_WithVerifiedAt(t *testing.T) {
	store := openTestDB(t)
	cryptoSvc := newCrypto(t)
	ctx := context.Background()

	verifiedAt := time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)

	data := &ExportData{
		Version:    1,
		ExportedAt: time.Now().UTC().Format(time.RFC3339),
		IdentityProviders: []ExportIDP{
			{
				ID: "idp-1", FriendlyName: "LDAP", ProviderType: "ad", Enabled: true,
				Config:  json.RawMessage(`{"host":"ldap.example.com"}`),
				Secrets: json.RawMessage(`{"password":"secret123"}`),
			},
		},
		UserMappings: []ExportMapping{
			{
				AuthProviderID:  "idp-1",
				AuthUsername:    "alice",
				TargetIDPID:     "idp-1",
				TargetAccountDN: "cn=alice,dc=example,dc=com",
				LinkType:        "manual",
				LinkedAt:        time.Now().UTC().Format(time.RFC3339),
				VerifiedAt:      &verifiedAt,
			},
		},
	}

	result, err := RunImport(ctx, store, cryptoSvc, data, AllSections())
	if err != nil {
		t.Fatalf("RunImport: %v", err)
	}
	if len(result.Errors) > 0 {
		t.Errorf("unexpected errors: %v", result.Errors)
	}
	if result.UserMappings != 1 {
		t.Errorf("expected 1 user mapping, got %d", result.UserMappings)
	}
}

// TestRunImport_DuoMFAProvider exercises importing a Duo MFA provider.
func TestRunImport_DuoMFAProvider(t *testing.T) {
	store := openTestDB(t)
	cryptoSvc := newCrypto(t)
	ctx := context.Background()

	data := &ExportData{
		Version:    1,
		ExportedAt: time.Now().UTC().Format(time.RFC3339),
		MFAProviders: []ExportMFAProvider{
			{
				ID:           "duo-1",
				Name:         "Duo MFA",
				ProviderType: "duo",
				Enabled:      true,
				// Valid DuoConfig JSON (ClientID must be 20 chars, but validation is at runtime)
				Config:  json.RawMessage(`{"client_id":"12345678901234567890","api_hostname":"api.duo.example.com","redirect_uri":"https://app.example.com/duo/callback"}`),
				Secrets: json.RawMessage(`{"client_secret":"1234567890123456789012345678901234567890"}`),
			},
		},
	}

	sections := ImportSections{MFA: true}
	result, err := RunImport(ctx, store, cryptoSvc, data, sections)
	if err != nil {
		t.Fatalf("RunImport: %v", err)
	}
	if result.MFAProviders != 1 {
		t.Errorf("expected 1 MFA provider imported, got %d", result.MFAProviders)
	}
}

// TestRunImport_InvalidDuoConfig exercises the Duo config unmarshal error path.
func TestRunImport_InvalidDuoConfig(t *testing.T) {
	store := openTestDB(t)
	cryptoSvc := newCrypto(t)
	ctx := context.Background()

	data := &ExportData{
		Version:    1,
		ExportedAt: time.Now().UTC().Format(time.RFC3339),
		MFAProviders: []ExportMFAProvider{
			{
				ID:           "duo-bad",
				Name:         "Duo Bad",
				ProviderType: "duo",
				Enabled:      true,
				Config:       json.RawMessage(`not-valid-json`),
				Secrets:      json.RawMessage(`{}`),
			},
		},
	}

	sections := ImportSections{MFA: true}
	result, err := RunImport(ctx, store, cryptoSvc, data, sections)
	if err != nil {
		t.Fatalf("RunImport itself should not fail: %v", err)
	}
	if len(result.Errors) == 0 {
		t.Error("expected error in result for invalid Duo config")
	}
	if result.MFAProviders != 0 {
		t.Errorf("expected 0 imported MFA providers, got %d", result.MFAProviders)
	}
}

// =============================================================================
// mockMigrateStore — embeds *db.DB and injects per-method errors
// =============================================================================

// mockMigrateStore wraps *db.DB and overrides specific methods to inject errors.
// Methods not overridden here delegate transparently to the embedded *db.DB.
type mockMigrateStore struct {
	*db.DB

	// Counter-based injectors: ListIDPs and ListMFAProviders are each called
	// twice in a BuildBackup/BuildExport call (once inside buildCommon, once in
	// the outer function). Set errAfter=1 to let the first call succeed and
	// fail the second.
	listIDPsCalls    int
	listIDPsErr      error
	listIDPsErrAfter int // fail when callCount > errAfter; 0 = always fail

	listMFAProvidersCalls    int
	listMFAProvidersErr      error
	listMFAProvidersErrAfter int

	// One-shot error injectors — non-nil value triggers the error.
	listLocalAdminsErr          error
	getLocalAdminErr            error
	updateLocalAdminPasswordErr error
	createLocalAdminErr         error
	updateIDPErr                error
	setAttributeMappingsErr     error
	setCorrelationRuleErr       error
	saveExpirationConfigErr     error
	saveExpirationFiltersErr    error
	getAdminGroupsByIDPErr      error
	deleteAdminGroupErr         error
	createAdminGroupErr         error
	upsertMappingErr            error
	saveSMTPConfigErr           error
	createMFAProviderErr        error
	updateMFAProviderErr        error
	setDefaultMFAProviderIDErr  error
	saveBrandingConfigErr       error
	saveEmailTemplateErr        error
}

func (m *mockMigrateStore) ListIDPs(ctx context.Context) ([]db.IdentityProviderRecord, error) {
	m.listIDPsCalls++
	if m.listIDPsErr != nil && (m.listIDPsErrAfter == 0 || m.listIDPsCalls > m.listIDPsErrAfter) {
		return nil, m.listIDPsErr
	}
	return m.DB.ListIDPs(ctx)
}

func (m *mockMigrateStore) ListMFAProviders(ctx context.Context) ([]db.MFAProviderRecord, error) {
	m.listMFAProvidersCalls++
	if m.listMFAProvidersErr != nil && (m.listMFAProvidersErrAfter == 0 || m.listMFAProvidersCalls > m.listMFAProvidersErrAfter) {
		return nil, m.listMFAProvidersErr
	}
	return m.DB.ListMFAProviders(ctx)
}

func (m *mockMigrateStore) ListLocalAdmins(ctx context.Context) ([]db.LocalAdmin, error) {
	if m.listLocalAdminsErr != nil {
		return nil, m.listLocalAdminsErr
	}
	return m.DB.ListLocalAdmins(ctx)
}

func (m *mockMigrateStore) GetLocalAdmin(ctx context.Context, username string) (*db.LocalAdmin, error) {
	if m.getLocalAdminErr != nil {
		return nil, m.getLocalAdminErr
	}
	return m.DB.GetLocalAdmin(ctx, username)
}

func (m *mockMigrateStore) UpdateLocalAdminPassword(ctx context.Context, username, passwordHash string, mustChange bool) error {
	if m.updateLocalAdminPasswordErr != nil {
		return m.updateLocalAdminPasswordErr
	}
	return m.DB.UpdateLocalAdminPassword(ctx, username, passwordHash, mustChange)
}

func (m *mockMigrateStore) CreateLocalAdmin(ctx context.Context, username, passwordHash string) (*db.LocalAdmin, error) {
	if m.createLocalAdminErr != nil {
		return nil, m.createLocalAdminErr
	}
	return m.DB.CreateLocalAdmin(ctx, username, passwordHash)
}

func (m *mockMigrateStore) UpdateIDP(ctx context.Context, idp *db.IdentityProviderRecord) error {
	if m.updateIDPErr != nil {
		return m.updateIDPErr
	}
	return m.DB.UpdateIDP(ctx, idp)
}

func (m *mockMigrateStore) SetAttributeMappings(ctx context.Context, idpID string, mappings []db.AttributeMapping) error {
	if m.setAttributeMappingsErr != nil {
		return m.setAttributeMappingsErr
	}
	return m.DB.SetAttributeMappings(ctx, idpID, mappings)
}

func (m *mockMigrateStore) SetCorrelationRule(ctx context.Context, rule *db.CorrelationRule) error {
	if m.setCorrelationRuleErr != nil {
		return m.setCorrelationRuleErr
	}
	return m.DB.SetCorrelationRule(ctx, rule)
}

func (m *mockMigrateStore) SaveExpirationConfig(ctx context.Context, cfg *db.ExpirationConfig) error {
	if m.saveExpirationConfigErr != nil {
		return m.saveExpirationConfigErr
	}
	return m.DB.SaveExpirationConfig(ctx, cfg)
}

func (m *mockMigrateStore) SaveExpirationFilters(ctx context.Context, idpID string, filters []db.ExpirationFilter) error {
	if m.saveExpirationFiltersErr != nil {
		return m.saveExpirationFiltersErr
	}
	return m.DB.SaveExpirationFilters(ctx, idpID, filters)
}

func (m *mockMigrateStore) GetAdminGroupsByIDP(ctx context.Context, idpID string) ([]db.AdminGroup, error) {
	if m.getAdminGroupsByIDPErr != nil {
		return nil, m.getAdminGroupsByIDPErr
	}
	return m.DB.GetAdminGroupsByIDP(ctx, idpID)
}

func (m *mockMigrateStore) DeleteAdminGroup(ctx context.Context, id int64) error {
	if m.deleteAdminGroupErr != nil {
		return m.deleteAdminGroupErr
	}
	return m.DB.DeleteAdminGroup(ctx, id)
}

func (m *mockMigrateStore) CreateAdminGroup(ctx context.Context, g *db.AdminGroup) error {
	if m.createAdminGroupErr != nil {
		return m.createAdminGroupErr
	}
	return m.DB.CreateAdminGroup(ctx, g)
}

func (m *mockMigrateStore) UpsertMapping(ctx context.Context, mapping *db.UserIDPMapping) error {
	if m.upsertMappingErr != nil {
		return m.upsertMappingErr
	}
	return m.DB.UpsertMapping(ctx, mapping)
}

func (m *mockMigrateStore) SaveSMTPConfig(ctx context.Context, cfg *db.SMTPConfig) error {
	if m.saveSMTPConfigErr != nil {
		return m.saveSMTPConfigErr
	}
	return m.DB.SaveSMTPConfig(ctx, cfg)
}

func (m *mockMigrateStore) CreateMFAProvider(ctx context.Context, p *db.MFAProviderRecord) error {
	if m.createMFAProviderErr != nil {
		return m.createMFAProviderErr
	}
	return m.DB.CreateMFAProvider(ctx, p)
}

func (m *mockMigrateStore) UpdateMFAProvider(ctx context.Context, p *db.MFAProviderRecord) error {
	if m.updateMFAProviderErr != nil {
		return m.updateMFAProviderErr
	}
	return m.DB.UpdateMFAProvider(ctx, p)
}

func (m *mockMigrateStore) SetDefaultMFAProviderID(ctx context.Context, id *string) error {
	if m.setDefaultMFAProviderIDErr != nil {
		return m.setDefaultMFAProviderIDErr
	}
	return m.DB.SetDefaultMFAProviderID(ctx, id)
}

func (m *mockMigrateStore) SaveBrandingConfig(ctx context.Context, cfg *db.BrandingConfig) error {
	if m.saveBrandingConfigErr != nil {
		return m.saveBrandingConfigErr
	}
	return m.DB.SaveBrandingConfig(ctx, cfg)
}

func (m *mockMigrateStore) SaveEmailTemplate(ctx context.Context, tmpl *db.EmailTemplate) error {
	if m.saveEmailTemplateErr != nil {
		return m.saveEmailTemplateErr
	}
	return m.DB.SaveEmailTemplate(ctx, tmpl)
}

// =============================================================================
// BuildBackup — additional error paths
// =============================================================================

// TestBuildBackup_BuildCommonError verifies that BuildBackup propagates an error
// returned by buildCommon (the shared internal helper).
func TestBuildBackup_BuildCommonError(t *testing.T) {
	database := openTestDB(t)
	store := &mockMigrateStore{
		DB:                 database,
		listLocalAdminsErr: fmt.Errorf("db read failed"),
	}

	_, err := BuildBackup(context.Background(), store)
	if err == nil {
		t.Error("expected error when buildCommon fails inside BuildBackup")
	}
}

// TestBuildBackup_ListIDPsError verifies that BuildBackup returns an error when
// the second ListIDPs call (after buildCommon) fails.
func TestBuildBackup_ListIDPsError(t *testing.T) {
	database := openTestDB(t)
	store := &mockMigrateStore{
		DB:               database,
		listIDPsErr:      fmt.Errorf("list IDPs failed"),
		listIDPsErrAfter: 1, // call #1 (buildCommon) succeeds; call #2 fails
	}

	_, err := BuildBackup(context.Background(), store)
	if err == nil {
		t.Error("expected error when ListIDPs fails after buildCommon in BuildBackup")
	}
}

// TestBuildBackup_ListMFAProvidersError verifies that BuildBackup returns an
// error when the second ListMFAProviders call (after buildCommon) fails.
func TestBuildBackup_ListMFAProvidersError(t *testing.T) {
	database := openTestDB(t)
	store := &mockMigrateStore{
		DB:                       database,
		listMFAProvidersErr:      fmt.Errorf("list MFA providers failed"),
		listMFAProvidersErrAfter: 1, // call #1 (buildCommon) succeeds; call #2 fails
	}

	_, err := BuildBackup(context.Background(), store)
	if err == nil {
		t.Error("expected error when ListMFAProviders fails after buildCommon in BuildBackup")
	}
}

// =============================================================================
// RunImport — local admin error paths
// =============================================================================

// TestRunImport_GetLocalAdminError verifies that a non-ErrNotFound error from
// GetLocalAdmin causes the admin to be skipped with a per-record error.
func TestRunImport_GetLocalAdminError(t *testing.T) {
	database := openTestDB(t)
	store := &mockMigrateStore{
		DB:               database,
		getLocalAdminErr: fmt.Errorf("db read error"),
	}
	cryptoSvc := newCrypto(t)

	data := &ExportData{
		Version: 1,
		LocalAdmins: []ExportLocalAdmin{
			{Username: "alice", PasswordHash: "hash", MustChangePassword: false},
		},
	}

	result, err := RunImport(context.Background(), store, cryptoSvc, data, ImportSections{Admins: true})
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if len(result.Errors) == 0 {
		t.Error("expected error when GetLocalAdmin returns unexpected error")
	}
	if result.LocalAdmins != 0 {
		t.Errorf("expected 0 local admins imported, got %d", result.LocalAdmins)
	}
}

// TestRunImport_UpdateExistingAdminError verifies that a failure in
// UpdateLocalAdminPassword (for an existing admin) is recorded as a per-record
// error and the admin is not counted.
func TestRunImport_UpdateExistingAdminError(t *testing.T) {
	database := openTestDB(t)
	ctx := context.Background()

	// Pre-create alice so the import takes the "update existing" path.
	if _, err := database.CreateLocalAdmin(ctx, "alice", "old-hash"); err != nil {
		t.Fatalf("creating admin: %v", err)
	}

	store := &mockMigrateStore{
		DB:                          database,
		updateLocalAdminPasswordErr: fmt.Errorf("update failed"),
	}
	cryptoSvc := newCrypto(t)

	data := &ExportData{
		Version: 1,
		LocalAdmins: []ExportLocalAdmin{
			{Username: "alice", PasswordHash: "new-hash", MustChangePassword: false},
		},
	}

	result, err := RunImport(ctx, store, cryptoSvc, data, ImportSections{Admins: true})
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if len(result.Errors) == 0 {
		t.Error("expected error when UpdateLocalAdminPassword fails for existing admin")
	}
	if result.LocalAdmins != 0 {
		t.Errorf("expected 0 local admins imported (update failed), got %d", result.LocalAdmins)
	}
}

// TestRunImport_CreateAdminError verifies that a failure in CreateLocalAdmin is
// recorded as a per-record error and the admin is not counted.
func TestRunImport_CreateAdminError(t *testing.T) {
	database := openTestDB(t)
	store := &mockMigrateStore{
		DB:                  database,
		createLocalAdminErr: fmt.Errorf("insert failed"),
	}
	cryptoSvc := newCrypto(t)

	data := &ExportData{
		Version: 1,
		LocalAdmins: []ExportLocalAdmin{
			{Username: "bob", PasswordHash: "hash", MustChangePassword: false},
		},
	}

	result, err := RunImport(context.Background(), store, cryptoSvc, data, ImportSections{Admins: true})
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if len(result.Errors) == 0 {
		t.Error("expected error when CreateLocalAdmin fails")
	}
	if result.LocalAdmins != 0 {
		t.Errorf("expected 0 local admins imported, got %d", result.LocalAdmins)
	}
}

// TestRunImport_UpdateAdminMustChangeFlagError verifies that a failure in the
// post-create UpdateLocalAdminPassword call (for !MustChangePassword) appends
// an error but still counts the admin as imported.
func TestRunImport_UpdateAdminMustChangeFlagError(t *testing.T) {
	database := openTestDB(t)
	store := &mockMigrateStore{
		DB:                          database,
		updateLocalAdminPasswordErr: fmt.Errorf("update flag failed"),
	}
	cryptoSvc := newCrypto(t)

	// Admin does not exist in DB → create path; MustChangePassword=false → update flag called.
	data := &ExportData{
		Version: 1,
		LocalAdmins: []ExportLocalAdmin{
			{Username: "charlie", PasswordHash: "hash", MustChangePassword: false},
		},
	}

	result, err := RunImport(context.Background(), store, cryptoSvc, data, ImportSections{Admins: true})
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if len(result.Errors) == 0 {
		t.Error("expected error when post-create UpdateLocalAdminPassword fails")
	}
	// The admin IS still counted even though the flag update failed.
	if result.LocalAdmins != 1 {
		t.Errorf("expected 1 local admin imported (create succeeded), got %d", result.LocalAdmins)
	}
}

// =============================================================================
// RunImport — IDP error paths
// =============================================================================

// TestRunImport_UpdateIDPError verifies that a failure in UpdateIDP (for an
// existing IDP) is recorded and the IDP is not counted.
func TestRunImport_UpdateIDPError(t *testing.T) {
	database := openTestDB(t)
	ctx := context.Background()

	// Pre-create the IDP so the import takes the "update" path.
	if err := database.CreateIDP(ctx, &db.IdentityProviderRecord{
		ID: "idp-1", FriendlyName: "Old", ProviderType: "ad", ConfigJSON: "{}",
	}); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	store := &mockMigrateStore{
		DB:           database,
		updateIDPErr: fmt.Errorf("update failed"),
	}
	cryptoSvc := newCrypto(t)

	data := &ExportData{
		Version: 1,
		IdentityProviders: []ExportIDP{
			{
				ID: "idp-1", FriendlyName: "New", ProviderType: "ad",
				Config:  json.RawMessage(`{}`),
				Secrets: json.RawMessage(`{}`),
			},
		},
	}

	result, err := RunImport(ctx, store, cryptoSvc, data, ImportSections{IDPs: true})
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if len(result.Errors) == 0 {
		t.Error("expected error when UpdateIDP fails")
	}
	if result.IDPs != 0 {
		t.Errorf("expected 0 IDPs imported (update failed), got %d", result.IDPs)
	}
}

// TestRunImport_SetAttributeMappingsError verifies that a failure in
// SetAttributeMappings appends a per-record error but still counts the IDP.
func TestRunImport_SetAttributeMappingsError(t *testing.T) {
	database := openTestDB(t)
	store := &mockMigrateStore{
		DB:                      database,
		setAttributeMappingsErr: fmt.Errorf("set mappings failed"),
	}
	cryptoSvc := newCrypto(t)

	data := &ExportData{
		Version: 1,
		IdentityProviders: []ExportIDP{
			{
				ID: "idp-1", FriendlyName: "LDAP", ProviderType: "ad",
				Config:  json.RawMessage(`{}`),
				Secrets: json.RawMessage(`{}`),
				AttributeMappings: []ExportAttrMapping{
					{CanonicalName: "email", DirectoryAttr: "mail"},
				},
			},
		},
	}

	result, err := RunImport(context.Background(), store, cryptoSvc, data, ImportSections{IDPs: true})
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if len(result.Errors) == 0 {
		t.Error("expected error when SetAttributeMappings fails")
	}
	// IDP is still counted even though attribute mappings failed.
	if result.IDPs != 1 {
		t.Errorf("expected 1 IDP imported (create succeeded), got %d", result.IDPs)
	}
}

// TestRunImport_SetCorrelationRuleError verifies that a failure in
// SetCorrelationRule appends an error but still counts the IDP.
func TestRunImport_SetCorrelationRuleError(t *testing.T) {
	database := openTestDB(t)
	store := &mockMigrateStore{
		DB:                    database,
		setCorrelationRuleErr: fmt.Errorf("set rule failed"),
	}
	cryptoSvc := newCrypto(t)

	data := &ExportData{
		Version: 1,
		IdentityProviders: []ExportIDP{
			{
				ID: "idp-1", FriendlyName: "LDAP", ProviderType: "ad",
				Config:  json.RawMessage(`{}`),
				Secrets: json.RawMessage(`{}`),
				CorrelationRule: &ExportCorrelationRule{
					SourceCanonicalAttr: "email",
					TargetDirectoryAttr: "userPrincipalName",
					MatchMode:           "exact",
				},
			},
		},
	}

	result, err := RunImport(context.Background(), store, cryptoSvc, data, ImportSections{IDPs: true})
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if len(result.Errors) == 0 {
		t.Error("expected error when SetCorrelationRule fails")
	}
	if result.IDPs != 1 {
		t.Errorf("expected 1 IDP imported, got %d", result.IDPs)
	}
}

// TestRunImport_SaveExpirationConfigError verifies that a failure in
// SaveExpirationConfig appends an error but still counts the IDP.
func TestRunImport_SaveExpirationConfigError(t *testing.T) {
	database := openTestDB(t)
	store := &mockMigrateStore{
		DB:                      database,
		saveExpirationConfigErr: fmt.Errorf("save expiration config failed"),
	}
	cryptoSvc := newCrypto(t)

	data := &ExportData{
		Version: 1,
		IdentityProviders: []ExportIDP{
			{
				ID: "idp-1", FriendlyName: "LDAP", ProviderType: "ad",
				Config:  json.RawMessage(`{}`),
				Secrets: json.RawMessage(`{}`),
				ExpirationConfig: &ExportExpirationConfig{
					Enabled: true, CronSchedule: "0 8 * * *", DaysBeforeExpiration: 14,
				},
			},
		},
	}

	result, err := RunImport(context.Background(), store, cryptoSvc, data, ImportSections{IDPs: true})
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if len(result.Errors) == 0 {
		t.Error("expected error when SaveExpirationConfig fails")
	}
	if result.IDPs != 1 {
		t.Errorf("expected 1 IDP imported, got %d", result.IDPs)
	}
}

// TestRunImport_SaveExpirationFiltersError verifies that a failure in
// SaveExpirationFilters appends an error but still counts the IDP.
func TestRunImport_SaveExpirationFiltersError(t *testing.T) {
	database := openTestDB(t)
	store := &mockMigrateStore{
		DB:                       database,
		saveExpirationFiltersErr: fmt.Errorf("save expiration filters failed"),
	}
	cryptoSvc := newCrypto(t)

	data := &ExportData{
		Version: 1,
		IdentityProviders: []ExportIDP{
			{
				ID: "idp-1", FriendlyName: "LDAP", ProviderType: "ad",
				Config:  json.RawMessage(`{}`),
				Secrets: json.RawMessage(`{}`),
				ExpirationFilters: []ExportExpirationFilter{
					{Attribute: "department", Pattern: "IT", Description: "IT dept"},
				},
			},
		},
	}

	result, err := RunImport(context.Background(), store, cryptoSvc, data, ImportSections{IDPs: true})
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if len(result.Errors) == 0 {
		t.Error("expected error when SaveExpirationFilters fails")
	}
	if result.IDPs != 1 {
		t.Errorf("expected 1 IDP imported, got %d", result.IDPs)
	}
}

// =============================================================================
// RunImport — admin group error paths
// =============================================================================

// TestRunImport_GetAdminGroupsByIDPError verifies that a failure in
// GetAdminGroupsByIDP is recorded and the iteration for that IDP is skipped,
// but CreateAdminGroup is still attempted for the import data.
func TestRunImport_GetAdminGroupsByIDPError(t *testing.T) {
	database := openTestDB(t)
	store := &mockMigrateStore{
		DB:                     database,
		getAdminGroupsByIDPErr: fmt.Errorf("list groups failed"),
	}
	cryptoSvc := newCrypto(t)

	data := &ExportData{
		Version: 1,
		AdminGroups: []ExportAdminGroup{
			{IDPID: "idp-1", GroupDN: "cn=admins,dc=example,dc=com", Description: "admins"},
		},
	}

	result, err := RunImport(context.Background(), store, cryptoSvc, data, ImportSections{Groups: true})
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if len(result.Errors) == 0 {
		t.Error("expected error when GetAdminGroupsByIDP fails")
	}
}

// TestRunImport_DeleteAdminGroupError verifies that a failure in DeleteAdminGroup
// is recorded. The existing group is not deleted, but the new group from import
// data is still created.
func TestRunImport_DeleteAdminGroupError(t *testing.T) {
	database := openTestDB(t)
	ctx := context.Background()

	// Pre-create the IDP so the admin group foreign key constraint is satisfied.
	if err := database.CreateIDP(ctx, &db.IdentityProviderRecord{
		ID: "idp-1", FriendlyName: "Test IDP", ProviderType: "ad", Enabled: true,
		ConfigJSON: `{"endpoint":"ldaps://dc.example.com"}`, SecretBlob: []byte("secret"),
	}); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	// Pre-create a group that will fail to delete.
	if err := database.CreateAdminGroup(ctx, &db.AdminGroup{
		IDPID: "idp-1", GroupDN: "cn=old,dc=example,dc=com", Description: "old group",
	}); err != nil {
		t.Fatalf("creating admin group: %v", err)
	}

	store := &mockMigrateStore{
		DB:                  database,
		deleteAdminGroupErr: fmt.Errorf("delete failed"),
	}
	cryptoSvc := newCrypto(t)

	// Import data has a different GroupDN so CreateAdminGroup won't hit a constraint.
	data := &ExportData{
		Version: 1,
		AdminGroups: []ExportAdminGroup{
			{IDPID: "idp-1", GroupDN: "cn=new,dc=example,dc=com", Description: "new group"},
		},
	}

	result, err := RunImport(ctx, store, cryptoSvc, data, ImportSections{Groups: true})
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if len(result.Errors) == 0 {
		t.Error("expected error when DeleteAdminGroup fails")
	}
}

// TestRunImport_CreateAdminGroupError verifies that a failure in CreateAdminGroup
// is recorded and the group is not counted.
func TestRunImport_CreateAdminGroupError(t *testing.T) {
	database := openTestDB(t)
	store := &mockMigrateStore{
		DB:                  database,
		createAdminGroupErr: fmt.Errorf("insert group failed"),
	}
	cryptoSvc := newCrypto(t)

	data := &ExportData{
		Version: 1,
		AdminGroups: []ExportAdminGroup{
			{IDPID: "idp-1", GroupDN: "cn=admins,dc=example,dc=com", Description: "admins"},
		},
	}

	result, err := RunImport(context.Background(), store, cryptoSvc, data, ImportSections{Groups: true})
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if len(result.Errors) == 0 {
		t.Error("expected error when CreateAdminGroup fails")
	}
	if result.AdminGroups != 0 {
		t.Errorf("expected 0 admin groups imported, got %d", result.AdminGroups)
	}
}

// =============================================================================
// RunImport — user mapping error paths
// =============================================================================

// TestRunImport_UpsertMappingError verifies that a failure in UpsertMapping is
// recorded and the mapping is not counted.
func TestRunImport_UpsertMappingError(t *testing.T) {
	database := openTestDB(t)
	store := &mockMigrateStore{
		DB:               database,
		upsertMappingErr: fmt.Errorf("upsert failed"),
	}
	cryptoSvc := newCrypto(t)

	data := &ExportData{
		Version: 1,
		UserMappings: []ExportMapping{
			{
				AuthProviderID:  "idp-1",
				AuthUsername:    "alice",
				TargetIDPID:     "idp-1",
				TargetAccountDN: "cn=alice,dc=example,dc=com",
				LinkType:        "manual",
				LinkedAt:        time.Now().UTC().Format(time.RFC3339),
			},
		},
	}

	result, err := RunImport(context.Background(), store, cryptoSvc, data, ImportSections{Mappings: true})
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if len(result.Errors) == 0 {
		t.Error("expected error when UpsertMapping fails")
	}
	if result.UserMappings != 0 {
		t.Errorf("expected 0 user mappings imported, got %d", result.UserMappings)
	}
}

// =============================================================================
// RunImport — SMTP error paths
// =============================================================================

// TestRunImport_SMTPSecretsResolveError verifies that a failure in resolveSecretBlob
// for SMTP (encrypted mode with invalid base64) appends an error and sets SMTP=false.
func TestRunImport_SMTPSecretsResolveError(t *testing.T) {
	database := openTestDB(t)
	store := &mockMigrateStore{DB: database}
	cryptoSvc := newCrypto(t)

	data := &ExportData{
		Version:          1,
		SecretsEncrypted: true, // backup mode: secrets should be base64
		SMTPConfig: &ExportSMTP{
			Config:  json.RawMessage(`{}`),
			Secrets: json.RawMessage(`"!!!not-valid-base64!!!"`), // invalid base64
		},
	}

	result, err := RunImport(context.Background(), store, cryptoSvc, data, ImportSections{SMTP: true})
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if len(result.Errors) == 0 {
		t.Error("expected error when SMTP resolveSecretBlob fails")
	}
	if result.SMTP {
		t.Error("expected SMTP=false when secrets resolution fails")
	}
}

// TestRunImport_SaveSMTPConfigError verifies that a failure in SaveSMTPConfig
// appends an error and sets SMTP=false.
func TestRunImport_SaveSMTPConfigError(t *testing.T) {
	database := openTestDB(t)
	store := &mockMigrateStore{
		DB:                database,
		saveSMTPConfigErr: fmt.Errorf("save smtp failed"),
	}
	cryptoSvc := newCrypto(t)

	data := &ExportData{
		Version: 1,
		SMTPConfig: &ExportSMTP{
			Config:  json.RawMessage(`{"host":"smtp.example.com"}`),
			Secrets: json.RawMessage(`{}`),
		},
	}

	result, err := RunImport(context.Background(), store, cryptoSvc, data, ImportSections{SMTP: true})
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if len(result.Errors) == 0 {
		t.Error("expected error when SaveSMTPConfig fails")
	}
	if result.SMTP {
		t.Error("expected SMTP=false when SaveSMTPConfig fails")
	}
}

// =============================================================================
// RunImport — MFA provider error paths
// =============================================================================

// TestRunImport_MFASecretsResolveError verifies that a failure in
// resolveSecretBlob for an MFA provider (encrypted mode, invalid base64) appends
// a per-record error and the provider is not counted.
func TestRunImport_MFASecretsResolveError(t *testing.T) {
	database := openTestDB(t)
	store := &mockMigrateStore{DB: database}
	cryptoSvc := newCrypto(t)

	data := &ExportData{
		Version:          1,
		SecretsEncrypted: true, // backup mode
		MFAProviders: []ExportMFAProvider{
			{
				ID:           "mfa-1",
				Name:         "Email MFA",
				ProviderType: "email",
				Enabled:      true,
				Config:       json.RawMessage(`{"from":"mfa@example.com"}`),
				Secrets:      json.RawMessage(`"!!!not-valid-base64!!!"`), // invalid base64
			},
		},
	}

	result, err := RunImport(context.Background(), store, cryptoSvc, data, ImportSections{MFA: true})
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if len(result.Errors) == 0 {
		t.Error("expected error when MFA resolveSecretBlob fails")
	}
	if result.MFAProviders != 0 {
		t.Errorf("expected 0 MFA providers imported, got %d", result.MFAProviders)
	}
}

// TestRunImport_CreateMFAProviderError verifies that a failure in
// CreateMFAProvider (for a new provider) is recorded and the provider is not counted.
func TestRunImport_CreateMFAProviderError(t *testing.T) {
	database := openTestDB(t)
	store := &mockMigrateStore{
		DB:                   database,
		createMFAProviderErr: fmt.Errorf("insert MFA failed"),
	}
	cryptoSvc := newCrypto(t)

	data := &ExportData{
		Version: 1,
		MFAProviders: []ExportMFAProvider{
			{
				ID: "mfa-new", Name: "Email MFA", ProviderType: "email", Enabled: true,
				Config:  json.RawMessage(`{"from":"mfa@example.com"}`),
				Secrets: json.RawMessage(`{}`),
			},
		},
	}

	result, err := RunImport(context.Background(), store, cryptoSvc, data, ImportSections{MFA: true})
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if len(result.Errors) == 0 {
		t.Error("expected error when CreateMFAProvider fails")
	}
	if result.MFAProviders != 0 {
		t.Errorf("expected 0 MFA providers imported, got %d", result.MFAProviders)
	}
}

// TestRunImport_UpdateMFAProviderError verifies that a failure in
// UpdateMFAProvider (for an existing provider) is recorded and the provider is
// not counted.
func TestRunImport_UpdateMFAProviderError(t *testing.T) {
	database := openTestDB(t)
	ctx := context.Background()

	// Pre-create the MFA provider so the import takes the "update" path.
	if err := database.CreateMFAProvider(ctx, &db.MFAProviderRecord{
		ID: "mfa-1", Name: "Email", ProviderType: "email", ConfigJSON: `{}`,
	}); err != nil {
		t.Fatalf("creating MFA provider: %v", err)
	}

	store := &mockMigrateStore{
		DB:                   database,
		updateMFAProviderErr: fmt.Errorf("update MFA failed"),
	}
	cryptoSvc := newCrypto(t)

	data := &ExportData{
		Version: 1,
		MFAProviders: []ExportMFAProvider{
			{
				ID: "mfa-1", Name: "Updated Email MFA", ProviderType: "email", Enabled: true,
				Config:  json.RawMessage(`{"from":"mfa@example.com"}`),
				Secrets: json.RawMessage(`{}`),
			},
		},
	}

	result, err := RunImport(ctx, store, cryptoSvc, data, ImportSections{MFA: true})
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if len(result.Errors) == 0 {
		t.Error("expected error when UpdateMFAProvider fails")
	}
	if result.MFAProviders != 0 {
		t.Errorf("expected 0 MFA providers imported (update failed), got %d", result.MFAProviders)
	}
}

// TestRunImport_SetDefaultMFAProviderIDError verifies that a failure in
// SetDefaultMFAProviderID appends an error but does not cause RunImport to return
// a hard error.
func TestRunImport_SetDefaultMFAProviderIDError(t *testing.T) {
	database := openTestDB(t)
	store := &mockMigrateStore{
		DB:                         database,
		setDefaultMFAProviderIDErr: fmt.Errorf("set default MFA failed"),
	}
	cryptoSvc := newCrypto(t)

	mfaID := "mfa-1"
	data := &ExportData{
		Version:              1,
		DefaultMFAProviderID: &mfaID,
	}

	result, err := RunImport(context.Background(), store, cryptoSvc, data, ImportSections{MFA: true})
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if len(result.Errors) == 0 {
		t.Error("expected error when SetDefaultMFAProviderID fails")
	}
}

// =============================================================================
// RunImport — branding and email template error paths
// =============================================================================

// TestRunImport_SaveBrandingError verifies that a failure in SaveBrandingConfig
// appends an error and sets Branding=false.
func TestRunImport_SaveBrandingError(t *testing.T) {
	database := openTestDB(t)
	store := &mockMigrateStore{
		DB:                    database,
		saveBrandingConfigErr: fmt.Errorf("save branding failed"),
	}
	cryptoSvc := newCrypto(t)

	data := &ExportData{
		Version: 1,
		Branding: &db.BrandingConfig{
			AppTitle: "MyApp", AppAbbreviation: "MA",
		},
	}

	result, err := RunImport(context.Background(), store, cryptoSvc, data, ImportSections{Branding: true})
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if len(result.Errors) == 0 {
		t.Error("expected error when SaveBrandingConfig fails")
	}
	if result.Branding {
		t.Error("expected Branding=false when SaveBrandingConfig fails")
	}
}

// TestRunImport_SaveEmailTemplateError verifies that a failure in
// SaveEmailTemplate appends an error and the template is not counted.
func TestRunImport_SaveEmailTemplateError(t *testing.T) {
	database := openTestDB(t)
	store := &mockMigrateStore{
		DB:                   database,
		saveEmailTemplateErr: fmt.Errorf("save template failed"),
	}
	cryptoSvc := newCrypto(t)

	data := &ExportData{
		Version: 1,
		EmailTemplates: []ExportEmailTemplate{
			{TemplateType: "password_reset", Subject: "Reset", BodyHTML: "<p>Reset</p>"},
		},
	}

	result, err := RunImport(context.Background(), store, cryptoSvc, data, ImportSections{Templates: true})
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if len(result.Errors) == 0 {
		t.Error("expected error when SaveEmailTemplate fails")
	}
	if result.EmailTemplates != 0 {
		t.Errorf("expected 0 email templates imported, got %d", result.EmailTemplates)
	}
}
