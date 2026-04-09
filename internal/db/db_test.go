package db

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// newTestDB creates an in-memory database with all migrations applied.
func newTestDB(t *testing.T) *DB {
	t.Helper()
	d, err := OpenMemory()
	if err != nil {
		t.Fatalf("opening memory db: %v", err)
	}
	if err := d.Migrate(context.Background()); err != nil {
		t.Fatalf("migrating: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func TestOpenMemoryAndMigrate(t *testing.T) {
	d := newTestDB(t)

	ctx := context.Background()
	complete, err := d.MigrationsComplete(ctx)
	if err != nil {
		t.Fatalf("checking migrations: %v", err)
	}
	if !complete {
		t.Error("expected migrations to be complete")
	}
}

func TestMigrateIdempotent(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	// Running migrate again should not error
	if err := d.Migrate(ctx); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
}

func TestPing(t *testing.T) {
	d := newTestDB(t)
	if err := d.Ping(context.Background()); err != nil {
		t.Fatalf("ping: %v", err)
	}
}

// --- Admin Store Tests ---

func TestCreateAndGetLocalAdmin(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	admin, err := d.CreateLocalAdmin(ctx, "admin", "$2a$10$hash")
	if err != nil {
		t.Fatalf("creating admin: %v", err)
	}
	if admin.Username != "admin" {
		t.Errorf("expected username admin, got %s", admin.Username)
	}
	if !admin.MustChangePassword {
		t.Error("expected must_change_password=true")
	}

	got, err := d.GetLocalAdmin(ctx, "admin")
	if err != nil {
		t.Fatalf("getting admin: %v", err)
	}
	if got.ID != admin.ID {
		t.Errorf("expected ID %d, got %d", admin.ID, got.ID)
	}
}

func TestGetLocalAdminNotFound(t *testing.T) {
	d := newTestDB(t)
	_, err := d.GetLocalAdmin(context.Background(), "nonexistent")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestCreateDuplicateAdmin(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	_, err := d.CreateLocalAdmin(ctx, "admin", "hash1")
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.CreateLocalAdmin(ctx, "admin", "hash2")
	if err == nil {
		t.Error("expected error for duplicate admin")
	}
}

func TestUpdateLocalAdminPassword(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	if _, err := d.CreateLocalAdmin(ctx, "admin", "oldhash"); err != nil {
		t.Fatalf("creating admin: %v", err)
	}
	err := d.UpdateLocalAdminPassword(ctx, "admin", "newhash", false)
	if err != nil {
		t.Fatalf("updating password: %v", err)
	}

	got, _ := d.GetLocalAdmin(ctx, "admin")
	if got.PasswordHash != "newhash" {
		t.Errorf("expected newhash, got %s", got.PasswordHash)
	}
	if got.MustChangePassword {
		t.Error("expected must_change_password=false")
	}
}

func TestUpdateLocalAdminPasswordNotFound(t *testing.T) {
	d := newTestDB(t)
	err := d.UpdateLocalAdminPassword(context.Background(), "ghost", "hash", false)
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

// --- IDP Store Tests ---

func createTestIDP(t *testing.T, d *DB, id string) *IdentityProviderRecord {
	t.Helper()
	idp := &IdentityProviderRecord{
		ID:           id,
		FriendlyName: "Test " + id,
		Description:  "Test provider",
		ProviderType: "ad",
		Enabled:      true,
		ConfigJSON:   `{"endpoint":"ldaps://dc.example.com"}`,
		SecretBlob:   []byte("encrypted-secret"),
	}
	if err := d.CreateIDP(context.Background(), idp); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}
	return idp
}

func TestIDPCRUD(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	// Create
	idp := createTestIDP(t, d, "corp-ad")

	// List all
	all, err := d.ListIDPs(ctx)
	if err != nil {
		t.Fatalf("listing IDPs: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("expected 1 IDP, got %d", len(all))
	}

	// Get
	got, err := d.GetIDP(ctx, "corp-ad")
	if err != nil {
		t.Fatalf("getting IDP: %v", err)
	}
	if got.FriendlyName != idp.FriendlyName {
		t.Errorf("expected %s, got %s", idp.FriendlyName, got.FriendlyName)
	}

	// Update
	got.FriendlyName = "Updated Name"
	if err := d.UpdateIDP(ctx, got); err != nil {
		t.Fatalf("updating IDP: %v", err)
	}
	got2, _ := d.GetIDP(ctx, "corp-ad")
	if got2.FriendlyName != "Updated Name" {
		t.Errorf("expected Updated Name, got %s", got2.FriendlyName)
	}

	// Toggle
	if err := d.ToggleIDP(ctx, "corp-ad", false); err != nil {
		t.Fatalf("toggling IDP: %v", err)
	}
	enabled, _ := d.ListEnabledIDPs(ctx)
	if len(enabled) != 0 {
		t.Errorf("expected 0 enabled IDPs, got %d", len(enabled))
	}

	// Delete
	if err := d.DeleteIDP(ctx, "corp-ad"); err != nil {
		t.Fatalf("deleting IDP: %v", err)
	}
	_, err = d.GetIDP(ctx, "corp-ad")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound after delete, got %v", err)
	}
}

func TestGetIDPNotFound(t *testing.T) {
	d := newTestDB(t)
	_, err := d.GetIDP(context.Background(), "nonexistent")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestAttributeMappings(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()
	createTestIDP(t, d, "corp-ad")

	mappings := []AttributeMapping{
		{IDPID: "corp-ad", CanonicalName: "email", DirectoryAttr: "mail"},
		{IDPID: "corp-ad", CanonicalName: "username", DirectoryAttr: "sAMAccountName"},
	}

	if err := d.SetAttributeMappings(ctx, "corp-ad", mappings); err != nil {
		t.Fatalf("setting mappings: %v", err)
	}

	got, err := d.ListAttributeMappings(ctx, "corp-ad")
	if err != nil {
		t.Fatalf("listing mappings: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 mappings, got %d", len(got))
	}

	// Replace with different mappings
	newMappings := []AttributeMapping{
		{IDPID: "corp-ad", CanonicalName: "email", DirectoryAttr: "userPrincipalName"},
	}
	if err := d.SetAttributeMappings(ctx, "corp-ad", newMappings); err != nil {
		t.Fatalf("replacing mappings: %v", err)
	}

	got2, _ := d.ListAttributeMappings(ctx, "corp-ad")
	if len(got2) != 1 {
		t.Fatalf("expected 1 mapping after replace, got %d", len(got2))
	}
	if got2[0].DirectoryAttr != "userPrincipalName" {
		t.Errorf("expected userPrincipalName, got %s", got2[0].DirectoryAttr)
	}
}

func TestCorrelationRules(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()
	createTestIDP(t, d, "corp-ad")

	rule := &CorrelationRule{
		IDPID:               "corp-ad",
		SourceCanonicalAttr: "email",
		TargetDirectoryAttr: "mail",
		MatchMode:           "exact",
	}
	if err := d.SetCorrelationRule(ctx, rule); err != nil {
		t.Fatalf("setting rule: %v", err)
	}

	got, err := d.GetCorrelationRule(ctx, "corp-ad")
	if err != nil {
		t.Fatalf("getting rule: %v", err)
	}
	if got.SourceCanonicalAttr != "email" {
		t.Errorf("expected email, got %s", got.SourceCanonicalAttr)
	}

	if err := d.DeleteCorrelationRule(ctx, "corp-ad"); err != nil {
		t.Fatalf("deleting rule: %v", err)
	}
	_, err = d.GetCorrelationRule(ctx, "corp-ad")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound after delete, got %v", err)
	}
}

// --- Session Store Tests ---

func TestSessionCRUD(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	s := &Session{
		ID:                 "sess-123",
		UserType:           "local",
		Username:           "admin",
		IsAdmin:            true,
		MustChangePassword: true,
		IPAddress:          "192.168.1.1",
		UserAgent:          "Mozilla/5.0",
		FlashJSON:          "{}",
		ExpiresAt:          time.Now().Add(8 * time.Hour).UTC(),
	}

	if err := d.CreateSession(ctx, s); err != nil {
		t.Fatalf("creating session: %v", err)
	}

	got, err := d.GetSession(ctx, "sess-123")
	if err != nil {
		t.Fatalf("getting session: %v", err)
	}
	if got.Username != "admin" {
		t.Errorf("expected admin, got %s", got.Username)
	}
	if !got.IsAdmin {
		t.Error("expected is_admin=true")
	}

	// Touch
	newExpiry := time.Now().Add(16 * time.Hour).UTC()
	if err := d.TouchSession(ctx, "sess-123", newExpiry); err != nil {
		t.Fatalf("touching session: %v", err)
	}

	// Update flash
	if err := d.UpdateSessionFlash(ctx, "sess-123", `{"msg":"hello"}`); err != nil {
		t.Fatalf("updating flash: %v", err)
	}
	got2, _ := d.GetSession(ctx, "sess-123")
	if got2.FlashJSON != `{"msg":"hello"}` {
		t.Errorf("expected flash update, got %s", got2.FlashJSON)
	}

	// Update must_change_password
	if err := d.UpdateSessionMustChangePassword(ctx, "sess-123", false); err != nil {
		t.Fatalf("updating must_change: %v", err)
	}
	got3, _ := d.GetSession(ctx, "sess-123")
	if got3.MustChangePassword {
		t.Error("expected must_change_password=false")
	}

	// Delete
	if err := d.DeleteSession(ctx, "sess-123"); err != nil {
		t.Fatalf("deleting session: %v", err)
	}
	_, err = d.GetSession(ctx, "sess-123")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound after delete, got %v", err)
	}
}

func TestSessionPurgeExpired(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	// Create expired session
	expired := &Session{
		ID: "expired", UserType: "local", Username: "u1",
		IPAddress: "1.1.1.1", FlashJSON: "{}",
		ExpiresAt: time.Now().Add(-1 * time.Hour).UTC(),
	}
	if err := d.CreateSession(ctx, expired); err != nil {
		t.Fatalf("creating expired session: %v", err)
	}

	// Create valid session
	valid := &Session{
		ID: "valid", UserType: "local", Username: "u2",
		IPAddress: "2.2.2.2", FlashJSON: "{}",
		ExpiresAt: time.Now().Add(1 * time.Hour).UTC(),
	}
	if err := d.CreateSession(ctx, valid); err != nil {
		t.Fatalf("creating valid session: %v", err)
	}

	count, err := d.PurgeExpired(ctx)
	if err != nil {
		t.Fatalf("purging: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 purged, got %d", count)
	}

	_, err = d.GetSession(ctx, "expired")
	if err != ErrNotFound {
		t.Error("expected expired session to be purged")
	}
	_, err = d.GetSession(ctx, "valid")
	if err != nil {
		t.Error("expected valid session to remain")
	}
}

// --- Audit Store Tests ---

func TestAuditAppendAndList(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	entries := []AuditEntry{
		{Username: "admin", SourceIP: "10.0.0.1", Action: "login", Result: "success", Details: "Local admin login"},
		{Username: "jsmith", SourceIP: "10.0.0.2", Action: "password_change", ProviderID: "corp-ad", ProviderName: "Corp AD", Result: "success", Details: "Password changed"},
		{Username: "jsmith", SourceIP: "10.0.0.2", Action: "login", Result: "failure", Details: "Bad password"},
	}

	for i := range entries {
		if err := d.AppendAudit(ctx, &entries[i]); err != nil {
			t.Fatalf("appending audit %d: %v", i, err)
		}
	}

	// List all
	got, total, err := d.ListAudit(ctx, AuditFilter{Limit: 50})
	if err != nil {
		t.Fatalf("listing audit: %v", err)
	}
	if total != 3 {
		t.Errorf("expected total 3, got %d", total)
	}
	if len(got) != 3 {
		t.Errorf("expected 3 entries, got %d", len(got))
	}

	// Filter by username
	got2, total2, _ := d.ListAudit(ctx, AuditFilter{Username: "jsmith", Limit: 50})
	if total2 != 2 {
		t.Errorf("expected 2 for jsmith, got %d", total2)
	}
	if len(got2) != 2 {
		t.Errorf("expected 2 entries for jsmith, got %d", len(got2))
	}

	// Filter by action
	got3, total3, _ := d.ListAudit(ctx, AuditFilter{Action: "login", Limit: 50})
	if total3 != 2 {
		t.Errorf("expected 2 login entries, got %d", total3)
	}
	_ = got3

	// Filter by result
	got4, total4, _ := d.ListAudit(ctx, AuditFilter{Result: "failure", Limit: 50})
	if total4 != 1 {
		t.Errorf("expected 1 failure, got %d", total4)
	}
	_ = got4

	// Pagination
	got5, _, _ := d.ListAudit(ctx, AuditFilter{Limit: 2, Offset: 0})
	if len(got5) != 2 {
		t.Errorf("expected 2 with limit 2, got %d", len(got5))
	}
}

// --- Mapping Store Tests ---

func TestMappingCRUD(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()
	createTestIDP(t, d, "corp-ad")
	createTestIDP(t, d, "ipa")

	m := &UserIDPMapping{
		AuthProviderID:  "ipa",
		AuthUsername:    "jsmith",
		TargetIDPID:     "corp-ad",
		TargetAccountDN: "CN=John Smith,OU=Users,DC=corp,DC=com",
		LinkType:        "auto",
	}
	if err := d.UpsertMapping(ctx, m); err != nil {
		t.Fatalf("upserting: %v", err)
	}

	got, err := d.GetMapping(ctx, "ipa", "jsmith", "corp-ad")
	if err != nil {
		t.Fatalf("getting mapping: %v", err)
	}
	if got.TargetAccountDN != m.TargetAccountDN {
		t.Errorf("expected %s, got %s", m.TargetAccountDN, got.TargetAccountDN)
	}
	if got.LinkType != "auto" {
		t.Errorf("expected auto, got %s", got.LinkType)
	}

	// Update verified
	now := time.Now().UTC()
	if err := d.UpdateMappingVerified(ctx, got.ID, now); err != nil {
		t.Fatalf("updating verified: %v", err)
	}

	got2, _ := d.GetMapping(ctx, "ipa", "jsmith", "corp-ad")
	if got2.VerifiedAt == nil {
		t.Error("expected verified_at to be set")
	}

	// List mappings
	all, err := d.ListMappings(ctx, "ipa", "jsmith")
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	if len(all) != 1 {
		t.Errorf("expected 1 mapping, got %d", len(all))
	}

	// Upsert (update existing)
	m.TargetAccountDN = "CN=John Smith,OU=Staff,DC=corp,DC=com"
	m.LinkType = "manual"
	if err := d.UpsertMapping(ctx, m); err != nil {
		t.Fatalf("upserting update: %v", err)
	}
	got3, _ := d.GetMapping(ctx, "ipa", "jsmith", "corp-ad")
	if got3.LinkType != "manual" {
		t.Errorf("expected manual after upsert, got %s", got3.LinkType)
	}

	// Delete single
	if err := d.DeleteMapping(ctx, got3.ID); err != nil {
		t.Fatalf("deleting: %v", err)
	}
	_, err = d.GetMapping(ctx, "ipa", "jsmith", "corp-ad")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound after delete, got %v", err)
	}
}

func TestDeleteAllMappings(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()
	createTestIDP(t, d, "corp-ad")
	createTestIDP(t, d, "ipa")

	if err := d.UpsertMapping(ctx, &UserIDPMapping{
		AuthProviderID: "ipa", AuthUsername: "jsmith",
		TargetIDPID: "corp-ad", TargetAccountDN: "cn=j", LinkType: "auto",
	}); err != nil {
		t.Fatalf("upserting mapping: %v", err)
	}
	if err := d.UpsertMapping(ctx, &UserIDPMapping{
		AuthProviderID: "ipa", AuthUsername: "jsmith",
		TargetIDPID: "ipa", TargetAccountDN: "uid=j", LinkType: "manual",
	}); err != nil {
		t.Fatalf("upserting mapping: %v", err)
	}

	count, err := d.DeleteAllMappings(ctx, "ipa", "jsmith")
	if err != nil {
		t.Fatalf("deleting all: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 deleted, got %d", count)
	}
}

// --- Settings Store Tests ---

func TestAdminGroups(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()
	createTestIDP(t, d, "corp-ad")

	g := &AdminGroup{
		IDPID:       "corp-ad",
		GroupDN:     "CN=PassPortAdmins,OU=Groups,DC=corp,DC=com",
		Description: "PassPort admin group",
	}
	if err := d.CreateAdminGroup(ctx, g); err != nil {
		t.Fatalf("creating group: %v", err)
	}

	all, err := d.ListAdminGroups(ctx)
	if err != nil {
		t.Fatalf("listing groups: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("expected 1 group, got %d", len(all))
	}
	if all[0].GroupDN != g.GroupDN {
		t.Errorf("expected %s, got %s", g.GroupDN, all[0].GroupDN)
	}

	// By IDP
	byIDP, _ := d.GetAdminGroupsByIDP(ctx, "corp-ad")
	if len(byIDP) != 1 {
		t.Errorf("expected 1 group by IDP, got %d", len(byIDP))
	}

	// Delete
	if err := d.DeleteAdminGroup(ctx, all[0].ID); err != nil {
		t.Fatalf("deleting group: %v", err)
	}
	after, _ := d.ListAdminGroups(ctx)
	if len(after) != 0 {
		t.Errorf("expected 0 groups after delete, got %d", len(after))
	}
}

func TestSMTPConfig(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	// Initially nil
	cfg, err := d.GetSMTPConfig(ctx)
	if err != nil {
		t.Fatalf("getting SMTP: %v", err)
	}
	if cfg != nil {
		t.Error("expected nil SMTP config initially")
	}

	// Save
	smtp := &SMTPConfig{
		ConfigJSON: `{"host":"smtp.example.com","port":587}`,
		SecretBlob: []byte("encrypted-creds"),
	}
	if err := d.SaveSMTPConfig(ctx, smtp); err != nil {
		t.Fatalf("saving SMTP: %v", err)
	}

	got, err := d.GetSMTPConfig(ctx)
	if err != nil {
		t.Fatalf("getting SMTP: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil SMTP config")
	}
	if got.ConfigJSON != smtp.ConfigJSON {
		t.Errorf("expected %s, got %s", smtp.ConfigJSON, got.ConfigJSON)
	}

	// Update (upsert)
	smtp.ConfigJSON = `{"host":"mail.example.com","port":465}`
	if err := d.SaveSMTPConfig(ctx, smtp); err != nil {
		t.Fatalf("updating SMTP: %v", err)
	}
	got2, _ := d.GetSMTPConfig(ctx)
	if got2.ConfigJSON != smtp.ConfigJSON {
		t.Errorf("expected updated config")
	}
}

// --- SearchMappings Tests ---

func TestSearchMappings_ByAuthProvider(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()
	createTestIDP(t, d, "idp-a")
	createTestIDP(t, d, "idp-b")

	m := &UserIDPMapping{
		AuthProviderID:  "idp-a",
		AuthUsername:    "jsmith",
		TargetIDPID:     "idp-b",
		TargetAccountDN: "CN=John Smith,OU=Users,DC=corp,DC=com",
		LinkType:        "auto",
		LinkedAt:        time.Now().UTC(),
	}
	if err := d.UpsertMapping(ctx, m); err != nil {
		t.Fatalf("upserting: %v", err)
	}

	// Search by auth_provider_id = "idp-a"
	results, _, err := d.SearchMappings(ctx, MappingSearchFilter{ProviderID: "idp-a", Username: "jsmith", Limit: 100})
	if err != nil {
		t.Fatalf("searching: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].TargetAccountDN != m.TargetAccountDN {
		t.Errorf("expected DN %s, got %s", m.TargetAccountDN, results[0].TargetAccountDN)
	}
}

func TestSearchMappings_ByTargetIDP(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()
	createTestIDP(t, d, "idp-a")
	createTestIDP(t, d, "idp-b")

	m := &UserIDPMapping{
		AuthProviderID:  "idp-a",
		AuthUsername:    "jsmith",
		TargetIDPID:     "idp-b",
		TargetAccountDN: "CN=John Smith,OU=Users,DC=corp,DC=com",
		LinkType:        "auto",
		LinkedAt:        time.Now().UTC(),
	}
	if err := d.UpsertMapping(ctx, m); err != nil {
		t.Fatalf("upserting: %v", err)
	}

	// Search by target_idp_id = "idp-b" should also find the mapping
	results, _, err := d.SearchMappings(ctx, MappingSearchFilter{ProviderID: "idp-b", Username: "jsmith", Limit: 100})
	if err != nil {
		t.Fatalf("searching: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].AuthProviderID != "idp-a" {
		t.Errorf("expected auth_provider_id idp-a, got %s", results[0].AuthProviderID)
	}
}

func TestSearchMappings_AllProviders(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()
	createTestIDP(t, d, "idp-a")
	createTestIDP(t, d, "idp-b")
	createTestIDP(t, d, "idp-c")

	// Create two mappings for jsmith with different auth providers
	if err := d.UpsertMapping(ctx, &UserIDPMapping{
		AuthProviderID: "idp-a", AuthUsername: "jsmith",
		TargetIDPID: "idp-b", TargetAccountDN: "cn=j,dc=b", LinkType: "auto",
		LinkedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("upserting mapping: %v", err)
	}
	if err := d.UpsertMapping(ctx, &UserIDPMapping{
		AuthProviderID: "idp-c", AuthUsername: "jsmith",
		TargetIDPID: "idp-a", TargetAccountDN: "cn=j,dc=a", LinkType: "manual",
		LinkedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("upserting mapping: %v", err)
	}

	// Search with empty providerID returns all mappings for username
	results, _, err := d.SearchMappings(ctx, MappingSearchFilter{Username: "jsmith", Limit: 100})
	if err != nil {
		t.Fatalf("searching: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
}

func TestSearchMappings_NoResults(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	results, _, err := d.SearchMappings(ctx, MappingSearchFilter{ProviderID: "nonexistent", Username: "nobody", Limit: 100})
	if err != nil {
		t.Fatalf("searching: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestListMappings_EmptyProvider(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()
	createTestIDP(t, d, "idp-a")
	createTestIDP(t, d, "idp-b")

	if err := d.UpsertMapping(ctx, &UserIDPMapping{
		AuthProviderID: "idp-a", AuthUsername: "jsmith",
		TargetIDPID: "idp-b", TargetAccountDN: "cn=j,dc=b", LinkType: "auto",
		LinkedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("upserting mapping: %v", err)
	}
	if err := d.UpsertMapping(ctx, &UserIDPMapping{
		AuthProviderID: "idp-b", AuthUsername: "jsmith",
		TargetIDPID: "idp-a", TargetAccountDN: "cn=j,dc=a", LinkType: "auto",
		LinkedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("upserting mapping: %v", err)
	}

	// Empty authProviderID returns all mappings for the username
	results, err := d.ListMappings(ctx, "", "jsmith")
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
}

// --- db.go / Open / Close Tests ---

func TestOpenAndClose(t *testing.T) {
	dir := t.TempDir()
	d, err := Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("opening db: %v", err)
	}
	if err := d.Migrate(context.Background()); err != nil {
		t.Fatalf("migrating: %v", err)
	}
	if d.Writer() == nil {
		t.Error("expected non-nil writer")
	}
	if d.Reader() == nil {
		t.Error("expected non-nil reader")
	}
	if err := d.Close(); err != nil {
		t.Fatalf("closing db: %v", err)
	}
}

func TestOpenInvalidPath(t *testing.T) {
	_, err := Open("/nonexistent/dir/db.sqlite")
	if err == nil {
		t.Error("expected error for invalid path, got nil")
	}
}

// --- Admin Store additional Tests ---

func TestListLocalAdmins(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	if _, err := d.CreateLocalAdmin(ctx, "admin1", "hash1"); err != nil {
		t.Fatalf("creating admin1: %v", err)
	}
	if _, err := d.CreateLocalAdmin(ctx, "admin2", "hash2"); err != nil {
		t.Fatalf("creating admin2: %v", err)
	}

	admins, err := d.ListLocalAdmins(ctx)
	if err != nil {
		t.Fatalf("listing local admins: %v", err)
	}
	if len(admins) < 2 {
		t.Errorf("expected at least 2 admins, got %d", len(admins))
	}
}

// --- Session Store additional Tests ---

func TestUpdateSessionMFA(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	s := &Session{
		ID:        "sess-mfa",
		UserType:  "local",
		Username:  "admin",
		IPAddress: "10.0.0.1",
		FlashJSON: "{}",
		ExpiresAt: time.Now().Add(8 * time.Hour).UTC(),
	}
	if err := d.CreateSession(ctx, s); err != nil {
		t.Fatalf("creating session: %v", err)
	}

	if err := d.UpdateSessionMFA(ctx, "sess-mfa", true, "pending"); err != nil {
		t.Fatalf("updating session MFA: %v", err)
	}

	got, err := d.GetSession(ctx, "sess-mfa")
	if err != nil {
		t.Fatalf("getting session: %v", err)
	}
	if !got.MFAPending {
		t.Error("expected MFAPending=true")
	}
	if got.MFAState != "pending" {
		t.Errorf("expected MFAState=pending, got %s", got.MFAState)
	}
}

func TestUpdateSessionMFA_NotFound(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	err := d.UpdateSessionMFA(ctx, "nonexistent-session", true, "pending")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestUpdateSessionMFAAttempts(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	s := &Session{
		ID:        "sess-mfa-attempts",
		UserType:  "local",
		Username:  "admin",
		IPAddress: "10.0.0.1",
		FlashJSON: "{}",
		ExpiresAt: time.Now().Add(8 * time.Hour).UTC(),
	}
	if err := d.CreateSession(ctx, s); err != nil {
		t.Fatalf("creating session: %v", err)
	}

	if err := d.UpdateSessionMFAAttempts(ctx, "sess-mfa-attempts", 2); err != nil {
		t.Fatalf("UpdateSessionMFAAttempts: %v", err)
	}

	got, err := d.GetSession(ctx, "sess-mfa-attempts")
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.MFAAttempts != 2 {
		t.Errorf("expected MFAAttempts=2, got %d", got.MFAAttempts)
	}

	// UpdateSessionMFA should reset attempts to 0.
	if err := d.UpdateSessionMFA(ctx, "sess-mfa-attempts", true, "state"); err != nil {
		t.Fatalf("UpdateSessionMFA: %v", err)
	}
	got, err = d.GetSession(ctx, "sess-mfa-attempts")
	if err != nil {
		t.Fatalf("GetSession after reset: %v", err)
	}
	if got.MFAAttempts != 0 {
		t.Errorf("expected MFAAttempts reset to 0 by UpdateSessionMFA, got %d", got.MFAAttempts)
	}
}

func TestUpdateSessionMFAAttempts_NotFound(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	err := d.UpdateSessionMFAAttempts(ctx, "nonexistent-session", 1)
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestTouchSession_NotFound(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	err := d.TouchSession(ctx, "nonexistent-session", time.Now().Add(time.Hour).UTC())
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestUpdateSessionFlash_NotFound(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	err := d.UpdateSessionFlash(ctx, "nonexistent-session", `{"msg":"hi"}`)
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestUpdateSessionMustChangePassword_NotFound(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	err := d.UpdateSessionMustChangePassword(ctx, "nonexistent-session", false)
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

// --- Mapping Store additional Tests ---

func TestHasMappingToTarget(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()
	createTestIDP(t, d, "idp-a")
	createTestIDP(t, d, "idp-b")

	if err := d.UpsertMapping(ctx, &UserIDPMapping{
		AuthProviderID:  "idp-a",
		AuthUsername:    "jsmith",
		TargetIDPID:     "idp-b",
		TargetAccountDN: "cn=jsmith,dc=b",
		LinkType:        "auto",
		LinkedAt:        time.Now().UTC(),
	}); err != nil {
		t.Fatalf("upserting mapping: %v", err)
	}

	found, err := d.HasMappingToTarget(ctx, "jsmith", "idp-b")
	if err != nil {
		t.Fatalf("HasMappingToTarget: %v", err)
	}
	if !found {
		t.Error("expected HasMappingToTarget=true for existing mapping")
	}

	found, err = d.HasMappingToTarget(ctx, "nobody", "idp-b")
	if err != nil {
		t.Fatalf("HasMappingToTarget (no match): %v", err)
	}
	if found {
		t.Error("expected HasMappingToTarget=false for non-existent username")
	}
}

func TestListAllMappings(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()
	createTestIDP(t, d, "idp-a")
	createTestIDP(t, d, "idp-b")

	if err := d.UpsertMapping(ctx, &UserIDPMapping{
		AuthProviderID: "idp-a", AuthUsername: "user1",
		TargetIDPID: "idp-b", TargetAccountDN: "cn=u1,dc=b", LinkType: "auto",
		LinkedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("upserting mapping: %v", err)
	}
	if err := d.UpsertMapping(ctx, &UserIDPMapping{
		AuthProviderID: "idp-b", AuthUsername: "user2",
		TargetIDPID: "idp-a", TargetAccountDN: "cn=u2,dc=a", LinkType: "manual",
		LinkedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("upserting mapping: %v", err)
	}

	all, err := d.ListAllMappings(ctx)
	if err != nil {
		t.Fatalf("ListAllMappings: %v", err)
	}
	if len(all) != 2 {
		t.Errorf("expected 2 mappings, got %d", len(all))
	}
}

func TestDowngradeMapping(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()
	createTestIDP(t, d, "idp-a")
	createTestIDP(t, d, "idp-b")

	m := &UserIDPMapping{
		AuthProviderID:  "idp-a",
		AuthUsername:    "jsmith",
		TargetIDPID:     "idp-b",
		TargetAccountDN: "cn=jsmith,dc=b",
		LinkType:        "auto",
		LinkedAt:        time.Now().UTC(),
	}
	if err := d.UpsertMapping(ctx, m); err != nil {
		t.Fatalf("upserting mapping: %v", err)
	}

	// m.ID is populated by UpsertMapping
	if err := d.DowngradeMapping(ctx, m.ID); err != nil {
		t.Fatalf("downgrading mapping: %v", err)
	}

	_, err := d.GetMapping(ctx, "idp-a", "jsmith", "idp-b")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound after downgrade, got %v", err)
	}
}

func TestDeleteMapping_NotFound(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	// DeleteMapping does not check rows affected, so a non-existent ID returns nil
	err := d.DeleteMapping(ctx, 999999)
	if err != nil {
		t.Errorf("expected nil error for non-existent mapping delete, got %v", err)
	}
}

// --- Email Template Tests ---

func TestEmailTemplates(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	// Migrations pre-seed several email templates; record the initial count.
	listInit, err := d.ListEmailTemplates(ctx)
	if err != nil {
		t.Fatalf("listing initial templates: %v", err)
	}
	initialCount := len(listInit)

	// GetEmailTemplate returns ErrNotFound for a type not in the seeded set
	_, err = d.GetEmailTemplate(ctx, "custom_test_template")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound for unknown template, got %v", err)
	}

	// Save a new template with a type not pre-seeded by migrations
	tmpl := &EmailTemplate{
		TemplateType: "custom_test_template",
		Subject:      "Custom test subject",
		BodyHTML:     "<p>Custom test body.</p>",
	}
	if err := d.SaveEmailTemplate(ctx, tmpl); err != nil {
		t.Fatalf("saving template: %v", err)
	}

	// Get by type
	got, err := d.GetEmailTemplate(ctx, "custom_test_template")
	if err != nil {
		t.Fatalf("getting template: %v", err)
	}
	if got.Subject != tmpl.Subject {
		t.Errorf("expected subject %q, got %q", tmpl.Subject, got.Subject)
	}
	if got.BodyHTML != tmpl.BodyHTML {
		t.Errorf("expected body %q, got %q", tmpl.BodyHTML, got.BodyHTML)
	}

	// Update (upsert) existing template
	tmpl.Subject = "Updated custom subject"
	if err := d.SaveEmailTemplate(ctx, tmpl); err != nil {
		t.Fatalf("updating template: %v", err)
	}
	got2, err := d.GetEmailTemplate(ctx, "custom_test_template")
	if err != nil {
		t.Fatalf("getting updated template: %v", err)
	}
	if got2.Subject != "Updated custom subject" {
		t.Errorf("expected updated subject, got %q", got2.Subject)
	}

	// ListEmailTemplates should show initialCount + 1
	list2, err := d.ListEmailTemplates(ctx)
	if err != nil {
		t.Fatalf("listing templates after save: %v", err)
	}
	if len(list2) != initialCount+1 {
		t.Errorf("expected %d templates, got %d", initialCount+1, len(list2))
	}

	// Delete the custom template
	if err := d.DeleteEmailTemplate(ctx, "custom_test_template"); err != nil {
		t.Fatalf("deleting template: %v", err)
	}

	// GetEmailTemplate returns ErrNotFound after delete
	_, err = d.GetEmailTemplate(ctx, "custom_test_template")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound after delete, got %v", err)
	}
}

// --- Expiration Config Tests ---

func TestExpirationConfig(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()
	createTestIDP(t, d, "idp-a")

	// GetExpirationConfig returns nil when not set
	cfg, err := d.GetExpirationConfig(ctx, "idp-a")
	if err != nil {
		t.Fatalf("getting expiration config (empty): %v", err)
	}
	if cfg != nil {
		t.Error("expected nil expiration config initially")
	}

	// Save a config
	newCfg := &ExpirationConfig{
		IDPID:                "idp-a",
		Enabled:              true,
		CronSchedule:         "0 6 * * *",
		DaysBeforeExpiration: 14,
	}
	if err := d.SaveExpirationConfig(ctx, newCfg); err != nil {
		t.Fatalf("saving expiration config: %v", err)
	}

	// GetExpirationConfig returns saved config
	got, err := d.GetExpirationConfig(ctx, "idp-a")
	if err != nil {
		t.Fatalf("getting expiration config: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil expiration config")
	}
	if !got.Enabled {
		t.Error("expected Enabled=true")
	}
	if got.CronSchedule != "0 6 * * *" {
		t.Errorf("expected cron '0 6 * * *', got %q", got.CronSchedule)
	}
	if got.DaysBeforeExpiration != 14 {
		t.Errorf("expected 14 days, got %d", got.DaysBeforeExpiration)
	}

	// ListEnabledExpirationConfigs returns the enabled config
	enabled, err := d.ListEnabledExpirationConfigs(ctx)
	if err != nil {
		t.Fatalf("listing enabled expiration configs: %v", err)
	}
	if len(enabled) != 1 {
		t.Errorf("expected 1 enabled config, got %d", len(enabled))
	}
}

func TestExpirationFilters(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()
	createTestIDP(t, d, "idp-a")

	filters := []ExpirationFilter{
		{IDPID: "idp-a", Attribute: "department", Pattern: "Engineering", Description: "Engineering dept"},
		{IDPID: "idp-a", Attribute: "userAccountControl", Pattern: "512", Description: "Normal accounts"},
	}
	if err := d.SaveExpirationFilters(ctx, "idp-a", filters); err != nil {
		t.Fatalf("saving expiration filters: %v", err)
	}

	got, err := d.ListExpirationFilters(ctx, "idp-a")
	if err != nil {
		t.Fatalf("listing expiration filters: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("expected 2 filters, got %d", len(got))
	}

	// SaveExpirationFilters with empty slice clears all filters
	if err := d.SaveExpirationFilters(ctx, "idp-a", []ExpirationFilter{}); err != nil {
		t.Fatalf("clearing expiration filters: %v", err)
	}

	got2, err := d.ListExpirationFilters(ctx, "idp-a")
	if err != nil {
		t.Fatalf("listing expiration filters after clear: %v", err)
	}
	if len(got2) != 0 {
		t.Errorf("expected 0 filters after clear, got %d", len(got2))
	}
}

// --- MFA Provider Tests ---

func TestMFAProviderCRUD(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	p := &MFAProviderRecord{
		ID:           "mfa-1",
		Name:         "Test MFA Provider",
		ProviderType: "duo",
		Enabled:      true,
		ConfigJSON:   `{"api_host":"api.example.com"}`,
		SecretBlob:   []byte("secret"),
	}
	if err := d.CreateMFAProvider(ctx, p); err != nil {
		t.Fatalf("creating MFA provider: %v", err)
	}

	// List
	list, err := d.ListMFAProviders(ctx)
	if err != nil {
		t.Fatalf("listing MFA providers: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("expected 1 MFA provider, got %d", len(list))
	}

	// Get
	got, err := d.GetMFAProvider(ctx, "mfa-1")
	if err != nil {
		t.Fatalf("getting MFA provider: %v", err)
	}
	if got.Name != p.Name {
		t.Errorf("expected name %q, got %q", p.Name, got.Name)
	}
	if !got.Enabled {
		t.Error("expected Enabled=true")
	}

	// Update
	got.Name = "Updated MFA Provider"
	if err := d.UpdateMFAProvider(ctx, got); err != nil {
		t.Fatalf("updating MFA provider: %v", err)
	}
	got2, _ := d.GetMFAProvider(ctx, "mfa-1")
	if got2.Name != "Updated MFA Provider" {
		t.Errorf("expected updated name, got %q", got2.Name)
	}

	// Toggle
	if err := d.ToggleMFAProvider(ctx, "mfa-1", false); err != nil {
		t.Fatalf("toggling MFA provider: %v", err)
	}
	got3, _ := d.GetMFAProvider(ctx, "mfa-1")
	if got3.Enabled {
		t.Error("expected Enabled=false after toggle")
	}

	// Delete
	if err := d.DeleteMFAProvider(ctx, "mfa-1"); err != nil {
		t.Fatalf("deleting MFA provider: %v", err)
	}

	// GetMFAProvider returns ErrNotFound after delete
	_, err = d.GetMFAProvider(ctx, "mfa-1")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound after delete, got %v", err)
	}
}

func TestGetEnabledMFAProvider(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	p := &MFAProviderRecord{
		ID:           "mfa-enabled",
		Name:         "Enabled Provider",
		ProviderType: "duo",
		Enabled:      true,
		ConfigJSON:   "{}",
	}
	if err := d.CreateMFAProvider(ctx, p); err != nil {
		t.Fatalf("creating MFA provider: %v", err)
	}

	got, err := d.GetEnabledMFAProvider(ctx)
	if err != nil {
		t.Fatalf("GetEnabledMFAProvider: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil enabled MFA provider")
	}
	if got.ID != "mfa-enabled" {
		t.Errorf("expected ID mfa-enabled, got %s", got.ID)
	}

	// Toggle disabled
	if err := d.ToggleMFAProvider(ctx, "mfa-enabled", false); err != nil {
		t.Fatalf("toggling provider: %v", err)
	}

	_, err = d.GetEnabledMFAProvider(ctx)
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound when no enabled provider, got %v", err)
	}
}

func TestMFAProviderForIDP_Direct(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()
	createTestIDP(t, d, "idp-a")

	p := &MFAProviderRecord{
		ID:           "mfa-direct",
		Name:         "Direct MFA Provider",
		ProviderType: "duo",
		Enabled:      true,
		ConfigJSON:   "{}",
	}
	if err := d.CreateMFAProvider(ctx, p); err != nil {
		t.Fatalf("creating MFA provider: %v", err)
	}

	// Assign mfa_provider_id directly on the IDP
	idp, err := d.GetIDP(ctx, "idp-a")
	if err != nil {
		t.Fatalf("getting IDP: %v", err)
	}
	idp.MFAProviderID = &p.ID
	if err := d.UpdateIDP(ctx, idp); err != nil {
		t.Fatalf("updating IDP with MFA provider: %v", err)
	}

	got, err := d.GetMFAProviderForIDP(ctx, "idp-a")
	if err != nil {
		t.Fatalf("GetMFAProviderForIDP: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil MFA provider for IDP")
	}
	if got.ID != "mfa-direct" {
		t.Errorf("expected MFA provider ID mfa-direct, got %s", got.ID)
	}
}

func TestMFAProviderForIDP_Default(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()
	createTestIDP(t, d, "idp-a") // no mfa_provider_id

	p := &MFAProviderRecord{
		ID:           "mfa-default",
		Name:         "Default MFA Provider",
		ProviderType: "duo",
		Enabled:      true,
		ConfigJSON:   "{}",
	}
	if err := d.CreateMFAProvider(ctx, p); err != nil {
		t.Fatalf("creating MFA provider: %v", err)
	}

	if err := d.SetDefaultMFAProviderID(ctx, &p.ID); err != nil {
		t.Fatalf("setting default MFA provider: %v", err)
	}

	got, err := d.GetMFAProviderForIDP(ctx, "idp-a")
	if err != nil {
		t.Fatalf("GetMFAProviderForIDP: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil default MFA provider for IDP")
	}
	if got.ID != "mfa-default" {
		t.Errorf("expected MFA provider ID mfa-default, got %s", got.ID)
	}
}

func TestMFAProviderForIDP_None(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()
	createTestIDP(t, d, "idp-a")

	// No MFA assigned and no default set
	got, err := d.GetMFAProviderForIDP(ctx, "idp-a")
	if err != nil {
		t.Fatalf("GetMFAProviderForIDP (none): %v", err)
	}
	if got != nil {
		t.Errorf("expected nil MFA provider when none configured, got %+v", got)
	}
}

func TestDefaultMFAProviderID(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	p := &MFAProviderRecord{
		ID:           "mfa-1",
		Name:         "Test Provider",
		ProviderType: "duo",
		Enabled:      true,
		ConfigJSON:   "{}",
	}
	if err := d.CreateMFAProvider(ctx, p); err != nil {
		t.Fatalf("creating MFA provider: %v", err)
	}

	// Set default
	if err := d.SetDefaultMFAProviderID(ctx, &p.ID); err != nil {
		t.Fatalf("setting default: %v", err)
	}

	// Get default
	got, err := d.GetDefaultMFAProviderID(ctx)
	if err != nil {
		t.Fatalf("getting default: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil default MFA provider ID")
	}
	if *got != "mfa-1" {
		t.Errorf("expected mfa-1, got %s", *got)
	}

	// Clear default
	if err := d.SetDefaultMFAProviderID(ctx, nil); err != nil {
		t.Fatalf("clearing default: %v", err)
	}

	got2, err := d.GetDefaultMFAProviderID(ctx)
	if err != nil {
		t.Fatalf("getting default after clear: %v", err)
	}
	if got2 != nil {
		t.Errorf("expected nil after clearing default, got %s", *got2)
	}
}

// --- Settings Store additional Tests ---

func TestBrandingConfig(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	// GetBrandingConfig returns defaults when no row is set
	cfg, err := d.GetBrandingConfig(ctx)
	if err != nil {
		t.Fatalf("getting branding config (default): %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil default branding config")
	}
	if cfg.AppTitle != "PassPort" {
		t.Errorf("expected default AppTitle 'PassPort', got %q", cfg.AppTitle)
	}

	// Save a custom config
	custom := &BrandingConfig{
		AppTitle:        "MyApp",
		AppAbbreviation: "MA",
		AppSubtitle:     "My Application",
		PrimaryColor:    "#123456",
	}
	if err := d.SaveBrandingConfig(ctx, custom); err != nil {
		t.Fatalf("saving branding config: %v", err)
	}

	// Get saved config
	got, err := d.GetBrandingConfig(ctx)
	if err != nil {
		t.Fatalf("getting branding config: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil branding config")
	}
	if got.AppTitle != "MyApp" {
		t.Errorf("expected AppTitle 'MyApp', got %q", got.AppTitle)
	}
	if got.PrimaryColor != "#123456" {
		t.Errorf("expected PrimaryColor '#123456', got %q", got.PrimaryColor)
	}
}

func TestListAdminGroups_Empty(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	groups, err := d.ListAdminGroups(ctx)
	if err != nil {
		t.Fatalf("listing admin groups on empty DB: %v", err)
	}
	if len(groups) != 0 {
		t.Errorf("expected 0 admin groups on fresh DB, got %d", len(groups))
	}
}

// --- Audit Store additional Tests ---

func TestPurgeAuditBefore(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	// Insert an "old" entry directly using the writer with a past timestamp
	oldTS := "2020-01-01T00:00:00.000Z"
	_, err := d.writer.ExecContext(ctx,
		`INSERT INTO audit_log (username, source_ip, action, result, details, timestamp)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		"old-user", "1.1.1.1", "login", "success", "old entry", oldTS)
	if err != nil {
		t.Fatalf("inserting old audit entry: %v", err)
	}

	// Insert a recent entry via AppendAudit (timestamp defaults to now)
	if err := d.AppendAudit(ctx, &AuditEntry{
		Username: "recent-user",
		SourceIP: "2.2.2.2",
		Action:   "login",
		Result:   "success",
		Details:  "recent entry",
	}); err != nil {
		t.Fatalf("appending recent audit: %v", err)
	}

	// Purge entries older than 1 hour ago — only the old entry qualifies
	cutoff := time.Now().UTC().Add(-1 * time.Hour)
	count, err := d.PurgeAuditBefore(ctx, cutoff)
	if err != nil {
		t.Fatalf("purging audit: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 purged (old entry), got %d", count)
	}

	// Verify recent entry remains
	entries, total, err := d.ListAudit(ctx, AuditFilter{Limit: 50})
	if err != nil {
		t.Fatalf("listing audit after purge: %v", err)
	}
	if total != 1 {
		t.Errorf("expected 1 remaining entry, got %d", total)
	}
	if len(entries) != 1 || entries[0].Username != "recent-user" {
		t.Errorf("expected recent-user entry to remain, got %+v", entries)
	}
}

// --- Migrate additional Tests ---

func TestMigrationsComplete_True(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	complete, err := d.MigrationsComplete(ctx)
	if err != nil {
		t.Fatalf("MigrationsComplete: %v", err)
	}
	if !complete {
		t.Error("expected MigrationsComplete=true after Migrate()")
	}
}

// --- Additional coverage tests ---

// TestAuditFilter_StartEndDate covers the StartDate and EndDate branches in buildAuditWhere.
func TestAuditFilter_StartEndDate(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	// Insert two entries (timestamps default to now)
	if err := d.AppendAudit(ctx, &AuditEntry{Username: "user1", Action: "login", Result: "success"}); err != nil {
		t.Fatalf("AppendAudit: %v", err)
	}
	if err := d.AppendAudit(ctx, &AuditEntry{Username: "user2", Action: "login", Result: "success"}); err != nil {
		t.Fatalf("AppendAudit: %v", err)
	}

	// Use StartDate and EndDate filters (future date range returns 0 results)
	farFuture := "2099-01-01T00:00:00.000Z"
	got, total, err := d.ListAudit(ctx, AuditFilter{
		StartDate: farFuture,
		EndDate:   farFuture,
		Limit:     50,
	})
	if err != nil {
		t.Fatalf("ListAudit with date filters: %v", err)
	}
	if total != 0 {
		t.Errorf("expected 0 results for future date range, got %d", total)
	}
	_ = got

	// Use StartDate in the past to capture our entries
	pastDate := "2000-01-01T00:00:00.000Z"
	got2, total2, err := d.ListAudit(ctx, AuditFilter{
		StartDate: pastDate,
		Limit:     50,
	})
	if err != nil {
		t.Fatalf("ListAudit with StartDate: %v", err)
	}
	if total2 < 2 {
		t.Errorf("expected at least 2 entries with past StartDate, got %d", total2)
	}
	_ = got2
}

// TestPing_WriterError covers the writer ping failure path in Ping.
func TestPing_WriterError(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	// Close the writer connection to force a ping failure
	d.writer.Close()

	err := d.Ping(ctx)
	if err == nil {
		t.Error("expected error when pinging closed writer, got nil")
	}
}

// TestUpsertMapping_WithVerifiedAt covers the VerifiedAt != nil branch in UpsertMapping.
func TestUpsertMapping_WithVerifiedAt(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()
	createTestIDP(t, d, "idp-a")
	createTestIDP(t, d, "idp-b")

	now := time.Now().UTC()
	m := &UserIDPMapping{
		AuthProviderID:  "idp-a",
		AuthUsername:    "verified-user",
		TargetIDPID:     "idp-b",
		TargetAccountDN: "cn=v,dc=b",
		LinkType:        "auto",
		LinkedAt:        now,
		VerifiedAt:      &now, // non-nil VerifiedAt exercises the branch in UpsertMapping
	}
	if err := d.UpsertMapping(ctx, m); err != nil {
		t.Fatalf("UpsertMapping with VerifiedAt: %v", err)
	}

	got, err := d.GetMapping(ctx, "idp-a", "verified-user", "idp-b")
	if err != nil {
		t.Fatalf("GetMapping: %v", err)
	}
	if got.VerifiedAt == nil {
		t.Error("expected VerifiedAt to be set after upsert with non-nil VerifiedAt")
	}
}

// TestSearchMappings_WithVerifiedAt covers the verifiedAt.Valid branch in SearchMappings.
func TestSearchMappings_WithVerifiedAt(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()
	createTestIDP(t, d, "idp-a")
	createTestIDP(t, d, "idp-b")

	// Insert mapping and then verify it
	m := &UserIDPMapping{
		AuthProviderID:  "idp-a",
		AuthUsername:    "sv-user",
		TargetIDPID:     "idp-b",
		TargetAccountDN: "cn=sv,dc=b",
		LinkType:        "auto",
		LinkedAt:        time.Now().UTC(),
	}
	if err := d.UpsertMapping(ctx, m); err != nil {
		t.Fatalf("upserting: %v", err)
	}
	if err := d.UpdateMappingVerified(ctx, m.ID, time.Now().UTC()); err != nil {
		t.Fatalf("updating verified: %v", err)
	}

	results, _, err := d.SearchMappings(ctx, MappingSearchFilter{ProviderID: "idp-a", Username: "sv-user", Limit: 100})
	if err != nil {
		t.Fatalf("SearchMappings: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].VerifiedAt == nil {
		t.Error("expected VerifiedAt to be populated in SearchMappings result")
	}
}

// TestListAllMappings_WithVerifiedAt covers the verifiedAt.Valid branch in ListAllMappings.
func TestListAllMappings_WithVerifiedAt(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()
	createTestIDP(t, d, "idp-a")
	createTestIDP(t, d, "idp-b")

	m := &UserIDPMapping{
		AuthProviderID:  "idp-a",
		AuthUsername:    "la-user",
		TargetIDPID:     "idp-b",
		TargetAccountDN: "cn=la,dc=b",
		LinkType:        "auto",
		LinkedAt:        time.Now().UTC(),
	}
	if err := d.UpsertMapping(ctx, m); err != nil {
		t.Fatalf("upserting: %v", err)
	}
	if err := d.UpdateMappingVerified(ctx, m.ID, time.Now().UTC()); err != nil {
		t.Fatalf("updating verified: %v", err)
	}

	all, err := d.ListAllMappings(ctx)
	if err != nil {
		t.Fatalf("ListAllMappings: %v", err)
	}
	if len(all) == 0 {
		t.Fatal("expected at least 1 mapping")
	}
	if all[0].VerifiedAt == nil {
		t.Error("expected VerifiedAt to be populated in ListAllMappings result")
	}
}

// --- Coverage: Ping reader error path ---

func TestPing_ReaderError(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	// Close the reader to force reader ping to fail; writer is still open
	d.reader.Close()

	err := d.Ping(ctx)
	if err == nil {
		t.Error("expected error when pinging closed reader, got nil")
	}
}

// --- Coverage: Malformed timestamps ---

// TestGetLocalAdmin_MalformedCreatedAt covers the time.Parse error for created_at in GetLocalAdmin.
func TestGetLocalAdmin_MalformedCreatedAt(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	_, err := d.writer.ExecContext(ctx,
		`INSERT INTO local_admins (username, password_hash, must_change_password, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?)`,
		"bad-ts-admin", "hash", 0, "not-a-date", "2024-01-01T00:00:00Z")
	if err != nil {
		t.Fatalf("inserting malformed row: %v", err)
	}

	_, err = d.GetLocalAdmin(ctx, "bad-ts-admin")
	if err == nil {
		t.Error("expected error for malformed created_at, got nil")
	}
}

// TestGetLocalAdmin_MalformedUpdatedAt covers the time.Parse error for updated_at in GetLocalAdmin.
func TestGetLocalAdmin_MalformedUpdatedAt(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	_, err := d.writer.ExecContext(ctx,
		`INSERT INTO local_admins (username, password_hash, must_change_password, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?)`,
		"bad-ua-admin", "hash", 0, "2024-01-01T00:00:00Z", "not-a-date")
	if err != nil {
		t.Fatalf("inserting malformed row: %v", err)
	}

	_, err = d.GetLocalAdmin(ctx, "bad-ua-admin")
	if err == nil {
		t.Error("expected error for malformed updated_at, got nil")
	}
}

// TestListLocalAdmins_MalformedTimestamp covers the time.Parse error branch in ListLocalAdmins.
func TestListLocalAdmins_MalformedTimestamp(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	_, err := d.writer.ExecContext(ctx,
		`INSERT INTO local_admins (username, password_hash, must_change_password, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?)`,
		"list-bad-ts", "hash", 0, "invalid", "2024-01-01T00:00:00Z")
	if err != nil {
		t.Fatalf("inserting malformed row: %v", err)
	}

	_, err = d.ListLocalAdmins(ctx)
	if err == nil {
		t.Error("expected error when listing admins with malformed timestamp")
	}
}

// TestGetSession_MalformedCreatedAt covers the time.Parse error for created_at in GetSession.
func TestGetSession_MalformedCreatedAt(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	_, err := d.writer.ExecContext(ctx,
		`INSERT INTO sessions (id, user_type, provider_id, username, is_admin, must_change_password,
		 ip_address, user_agent, flash_json, mfa_pending, mfa_state, created_at, expires_at, last_activity_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"sess-bad-ca", "local", "", "u", 0, 0, "1.1.1.1", "", "{}", 0, "",
		"NOT-A-DATE", "2099-01-01T00:00:00Z", "2024-01-01T00:00:00Z")
	if err != nil {
		t.Fatalf("inserting malformed row: %v", err)
	}

	_, err = d.GetSession(ctx, "sess-bad-ca")
	if err == nil {
		t.Error("expected error for malformed created_at")
	}
}

// TestGetSession_MalformedExpiresAt covers the time.Parse error for expires_at in GetSession.
func TestGetSession_MalformedExpiresAt(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	_, err := d.writer.ExecContext(ctx,
		`INSERT INTO sessions (id, user_type, provider_id, username, is_admin, must_change_password,
		 ip_address, user_agent, flash_json, mfa_pending, mfa_state, created_at, expires_at, last_activity_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"sess-bad-ea", "local", "", "u", 0, 0, "1.1.1.1", "", "{}", 0, "",
		"2024-01-01T00:00:00Z", "NOT-A-DATE", "2024-01-01T00:00:00Z")
	if err != nil {
		t.Fatalf("inserting malformed row: %v", err)
	}

	_, err = d.GetSession(ctx, "sess-bad-ea")
	if err == nil {
		t.Error("expected error for malformed expires_at")
	}
}

// TestGetSession_MalformedLastActivity covers the time.Parse error for last_activity_at in GetSession.
func TestGetSession_MalformedLastActivity(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	_, err := d.writer.ExecContext(ctx,
		`INSERT INTO sessions (id, user_type, provider_id, username, is_admin, must_change_password,
		 ip_address, user_agent, flash_json, mfa_pending, mfa_state, created_at, expires_at, last_activity_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"sess-bad-la", "local", "", "u", 0, 0, "1.1.1.1", "", "{}", 0, "",
		"2024-01-01T00:00:00Z", "2099-01-01T00:00:00Z", "NOT-A-DATE")
	if err != nil {
		t.Fatalf("inserting malformed row: %v", err)
	}

	_, err = d.GetSession(ctx, "sess-bad-la")
	if err == nil {
		t.Error("expected error for malformed last_activity_at")
	}
}

// TestGetBrandingConfig_InvalidJSON covers the json.Unmarshal error in GetBrandingConfig.
func TestGetBrandingConfig_InvalidJSON(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	_, err := d.writer.ExecContext(ctx,
		`INSERT INTO branding_config (id, config_json, updated_at) VALUES (1, ?, strftime('%Y-%m-%dT%H:%M:%SZ','now'))
		 ON CONFLICT(id) DO UPDATE SET config_json = excluded.config_json`,
		"this is not json {{{")
	if err != nil {
		t.Fatalf("inserting invalid JSON: %v", err)
	}

	_, err = d.GetBrandingConfig(ctx)
	if err == nil {
		t.Error("expected error for invalid branding config JSON, got nil")
	}
}

// TestGetDefaultMFAProviderID_NoSettingsRow covers the sql.ErrNoRows path in GetDefaultMFAProviderID.
func TestGetDefaultMFAProviderID_NoSettingsRow(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	// Delete the singleton mfa_settings row to trigger ErrNoRows
	if _, err := d.writer.ExecContext(ctx, `DELETE FROM mfa_settings WHERE id = 1`); err != nil {
		t.Fatalf("deleting mfa_settings row: %v", err)
	}

	id, err := d.GetDefaultMFAProviderID(ctx)
	if err != nil {
		t.Fatalf("expected nil error (ErrNoRows path), got %v", err)
	}
	if id != nil {
		t.Errorf("expected nil id when no settings row, got %s", *id)
	}
}

// --- Coverage: write-operation errors when writer is closed ---

// TestWriteErrors_ClosedWriter covers ExecContext error paths for write operations.
func TestWriteErrors_ClosedWriter(t *testing.T) {
	ctx := context.Background()

	run := func(name string, fn func(*DB) error) {
		t.Run(name, func(t *testing.T) {
			d := newTestDB(t)
			d.writer.Close()
			err := fn(d)
			if err == nil {
				t.Errorf("%s: expected error with closed writer, got nil", name)
			}
		})
	}

	run("AppendAudit", func(d *DB) error {
		return d.AppendAudit(ctx, &AuditEntry{Action: "login", Result: "success"})
	})
	run("CreateLocalAdmin", func(d *DB) error {
		_, err := d.CreateLocalAdmin(ctx, "u", "h")
		return err
	})
	run("UpdateLocalAdminPassword", func(d *DB) error {
		return d.UpdateLocalAdminPassword(ctx, "u", "h", false)
	})
	run("CreateSession", func(d *DB) error {
		return d.CreateSession(ctx, &Session{
			ID: "s1", UserType: "local", Username: "u",
			IPAddress: "1.1.1.1", FlashJSON: "{}",
			ExpiresAt: time.Now().Add(time.Hour).UTC(),
		})
	})
	run("DeleteSession", func(d *DB) error {
		return d.DeleteSession(ctx, "nonexistent")
	})
	run("PurgeExpired", func(d *DB) error {
		_, err := d.PurgeExpired(ctx)
		return err
	})
	run("SaveSMTPConfig", func(d *DB) error {
		return d.SaveSMTPConfig(ctx, &SMTPConfig{ConfigJSON: "{}"})
	})
	run("SaveBrandingConfig", func(d *DB) error {
		return d.SaveBrandingConfig(ctx, &BrandingConfig{AppTitle: "T"})
	})
	run("CreateAdminGroup", func(d *DB) error {
		return d.CreateAdminGroup(ctx, &AdminGroup{IDPID: "x", GroupDN: "cn=x"})
	})
	run("DeleteAdminGroup", func(d *DB) error {
		return d.DeleteAdminGroup(ctx, 1)
	})
	run("UpsertMapping", func(d *DB) error {
		return d.UpsertMapping(ctx, &UserIDPMapping{
			AuthProviderID: "a", AuthUsername: "u", TargetIDPID: "b",
			TargetAccountDN: "cn=u", LinkType: "auto", LinkedAt: time.Now().UTC(),
		})
	})
	run("UpdateMappingVerified", func(d *DB) error {
		return d.UpdateMappingVerified(ctx, 1, time.Now().UTC())
	})
	run("DeleteMapping", func(d *DB) error {
		return d.DeleteMapping(ctx, 1)
	})
	run("DeleteAllMappings", func(d *DB) error {
		_, err := d.DeleteAllMappings(ctx, "a", "u")
		return err
	})
	run("DowngradeMapping", func(d *DB) error {
		return d.DowngradeMapping(ctx, 1)
	})
	run("CreateMFAProvider", func(d *DB) error {
		return d.CreateMFAProvider(ctx, &MFAProviderRecord{
			ID: "m1", Name: "M", ProviderType: "duo", ConfigJSON: "{}",
		})
	})
	run("UpdateMFAProvider", func(d *DB) error {
		return d.UpdateMFAProvider(ctx, &MFAProviderRecord{
			ID: "m1", Name: "M", ProviderType: "duo", ConfigJSON: "{}",
		})
	})
	run("DeleteMFAProvider", func(d *DB) error {
		return d.DeleteMFAProvider(ctx, "m1")
	})
	run("ToggleMFAProvider", func(d *DB) error {
		return d.ToggleMFAProvider(ctx, "m1", true)
	})
	run("SetDefaultMFAProviderID", func(d *DB) error {
		s := "m1"
		return d.SetDefaultMFAProviderID(ctx, &s)
	})
	run("SaveExpirationConfig", func(d *DB) error {
		return d.SaveExpirationConfig(ctx, &ExpirationConfig{IDPID: "i", CronSchedule: "0 6 * * *"})
	})
	run("SaveEmailTemplate", func(d *DB) error {
		return d.SaveEmailTemplate(ctx, &EmailTemplate{TemplateType: "t", Subject: "s", BodyHTML: "<p/>"})
	})
	run("DeleteEmailTemplate", func(d *DB) error {
		return d.DeleteEmailTemplate(ctx, "nonexistent")
	})
	run("PurgeAuditBefore", func(d *DB) error {
		_, err := d.PurgeAuditBefore(ctx, time.Now())
		return err
	})
	run("CreateIDP", func(d *DB) error {
		return d.CreateIDP(ctx, &IdentityProviderRecord{
			ID: "i1", FriendlyName: "I", ProviderType: "ad", ConfigJSON: "{}",
		})
	})
	run("DeleteIDP", func(d *DB) error {
		return d.DeleteIDP(ctx, "nonexistent")
	})
	run("ToggleIDP", func(d *DB) error {
		return d.ToggleIDP(ctx, "nonexistent", true)
	})
	run("SetCorrelationRule", func(d *DB) error {
		return d.SetCorrelationRule(ctx, &CorrelationRule{
			IDPID: "i", SourceCanonicalAttr: "a", TargetDirectoryAttr: "b", MatchMode: "exact",
		})
	})
	run("DeleteCorrelationRule", func(d *DB) error {
		return d.DeleteCorrelationRule(ctx, "nonexistent")
	})
}

// --- Coverage: read-operation errors when reader is closed ---

// TestReadErrors_ClosedReader covers QueryContext/QueryRowContext error paths.
func TestReadErrors_ClosedReader(t *testing.T) {
	ctx := context.Background()

	run := func(name string, fn func(*DB) error) {
		t.Run(name, func(t *testing.T) {
			d := newTestDB(t)
			d.reader.Close()
			err := fn(d)
			if err == nil {
				t.Errorf("%s: expected error with closed reader, got nil", name)
			}
		})
	}

	run("GetLocalAdmin", func(d *DB) error {
		_, err := d.GetLocalAdmin(ctx, "u")
		return err
	})
	run("ListLocalAdmins", func(d *DB) error {
		_, err := d.ListLocalAdmins(ctx)
		return err
	})
	run("ListAudit", func(d *DB) error {
		_, _, err := d.ListAudit(ctx, AuditFilter{Limit: 10})
		return err
	})
	run("GetSession", func(d *DB) error {
		_, err := d.GetSession(ctx, "s")
		return err
	})
	run("ListIDPs", func(d *DB) error {
		_, err := d.ListIDPs(ctx)
		return err
	})
	run("ListEnabledIDPs", func(d *DB) error {
		_, err := d.ListEnabledIDPs(ctx)
		return err
	})
	run("GetIDP", func(d *DB) error {
		_, err := d.GetIDP(ctx, "i")
		return err
	})
	run("ListAttributeMappings", func(d *DB) error {
		_, err := d.ListAttributeMappings(ctx, "i")
		return err
	})
	run("GetCorrelationRule", func(d *DB) error {
		_, err := d.GetCorrelationRule(ctx, "i")
		return err
	})
	run("GetMapping", func(d *DB) error {
		_, err := d.GetMapping(ctx, "a", "u", "b")
		return err
	})
	run("HasMappingToTarget", func(d *DB) error {
		_, err := d.HasMappingToTarget(ctx, "u", "b")
		return err
	})
	run("ListMappings", func(d *DB) error {
		_, err := d.ListMappings(ctx, "a", "u")
		return err
	})
	run("SearchMappings", func(d *DB) error {
		_, _, err := d.SearchMappings(ctx, MappingSearchFilter{ProviderID: "a", Username: "u", Limit: 100})
		return err
	})
	run("ListAllMappings", func(d *DB) error {
		_, err := d.ListAllMappings(ctx)
		return err
	})
	run("ListAdminGroups", func(d *DB) error {
		_, err := d.ListAdminGroups(ctx)
		return err
	})
	run("GetAdminGroupsByIDP", func(d *DB) error {
		_, err := d.GetAdminGroupsByIDP(ctx, "i")
		return err
	})
	run("GetSMTPConfig", func(d *DB) error {
		_, err := d.GetSMTPConfig(ctx)
		return err
	})
	run("GetBrandingConfig", func(d *DB) error {
		_, err := d.GetBrandingConfig(ctx)
		return err
	})
	run("ListMFAProviders", func(d *DB) error {
		_, err := d.ListMFAProviders(ctx)
		return err
	})
	run("GetMFAProvider", func(d *DB) error {
		_, err := d.GetMFAProvider(ctx, "m")
		return err
	})
	run("GetEnabledMFAProvider", func(d *DB) error {
		_, err := d.GetEnabledMFAProvider(ctx)
		return err
	})
	run("GetMFAProviderForIDP", func(d *DB) error {
		_, err := d.GetMFAProviderForIDP(ctx, "i")
		return err
	})
	run("GetDefaultMFAProviderID", func(d *DB) error {
		_, err := d.GetDefaultMFAProviderID(ctx)
		return err
	})
	run("GetExpirationConfig", func(d *DB) error {
		_, err := d.GetExpirationConfig(ctx, "i")
		return err
	})
	run("ListExpirationFilters", func(d *DB) error {
		_, err := d.ListExpirationFilters(ctx, "i")
		return err
	})
	run("ListEnabledExpirationConfigs", func(d *DB) error {
		_, err := d.ListEnabledExpirationConfigs(ctx)
		return err
	})
	run("ListEmailTemplates", func(d *DB) error {
		_, err := d.ListEmailTemplates(ctx)
		return err
	})
	run("GetEmailTemplate", func(d *DB) error {
		_, err := d.GetEmailTemplate(ctx, "t")
		return err
	})
}

// --- Coverage: SetAttributeMappings and SaveExpirationFilters transaction errors ---

// TestSetAttributeMappings_WriterError covers the BeginTx error in SetAttributeMappings.
func TestSetAttributeMappings_WriterError(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()
	d.writer.Close()

	err := d.SetAttributeMappings(ctx, "idp-a", []AttributeMapping{
		{IDPID: "idp-a", CanonicalName: "email", DirectoryAttr: "mail"},
	})
	if err == nil {
		t.Error("expected error with closed writer, got nil")
	}
}

// TestSaveExpirationFilters_WriterError covers the BeginTx error in SaveExpirationFilters.
func TestSaveExpirationFilters_WriterError(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()
	d.writer.Close()

	err := d.SaveExpirationFilters(ctx, "idp-a", []ExpirationFilter{
		{Attribute: "attr", Pattern: "val"},
	})
	if err == nil {
		t.Error("expected error with closed writer, got nil")
	}
}

// --- Coverage: UpdateIDP and UpdateMFAProvider writer errors ---

// TestUpdateIDP_WriterError covers the ExecContext error path in UpdateIDP.
func TestUpdateIDP_WriterError(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()
	d.writer.Close()

	err := d.UpdateIDP(ctx, &IdentityProviderRecord{
		ID: "i1", FriendlyName: "I", ProviderType: "ad", ConfigJSON: "{}",
	})
	if err == nil {
		t.Error("expected error with closed writer, got nil")
	}
}

// --- ErrNotFound coverage for update/delete operations ---

func TestUpdateIDP_NotFound(t *testing.T) {
	d := newTestDB(t)
	err := d.UpdateIDP(context.Background(), &IdentityProviderRecord{
		ID: "no-such-idp", FriendlyName: "X", ProviderType: "ad", ConfigJSON: "{}",
	})
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestDeleteIDP_NotFound(t *testing.T) {
	d := newTestDB(t)
	err := d.DeleteIDP(context.Background(), "no-such-idp")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestToggleIDP_NotFound(t *testing.T) {
	d := newTestDB(t)
	err := d.ToggleIDP(context.Background(), "no-such-idp", true)
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestDeleteCorrelationRule_NotFound(t *testing.T) {
	d := newTestDB(t)
	err := d.DeleteCorrelationRule(context.Background(), "no-such-idp")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestUpdateMappingVerified_NotFound(t *testing.T) {
	d := newTestDB(t)
	err := d.UpdateMappingVerified(context.Background(), 999999, time.Now().UTC())
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestDowngradeMapping_NotFound(t *testing.T) {
	d := newTestDB(t)
	err := d.DowngradeMapping(context.Background(), 999999)
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestUpdateMFAProvider_NotFound(t *testing.T) {
	d := newTestDB(t)
	err := d.UpdateMFAProvider(context.Background(), &MFAProviderRecord{
		ID: "no-such-mfa", Name: "X", ProviderType: "duo", ConfigJSON: "{}",
	})
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestDeleteMFAProvider_NotFound(t *testing.T) {
	d := newTestDB(t)
	err := d.DeleteMFAProvider(context.Background(), "no-such-mfa")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestToggleMFAProvider_NotFound(t *testing.T) {
	d := newTestDB(t)
	err := d.ToggleMFAProvider(context.Background(), "no-such-mfa", true)
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestDeleteAdminGroup_NotFound(t *testing.T) {
	d := newTestDB(t)
	err := d.DeleteAdminGroup(context.Background(), 999999)
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestDeleteEmailTemplate_NotFound(t *testing.T) {
	d := newTestDB(t)
	err := d.DeleteEmailTemplate(context.Background(), "nonexistent_template_9999")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

// --- Branch coverage: boolean flag true-branch ---

// TestUpdateLocalAdminPassword_MustChangeTrue covers the mustChangeInt = 1 branch.
func TestUpdateLocalAdminPassword_MustChangeTrue(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()
	if _, err := d.CreateLocalAdmin(ctx, "admin-mct", "hash"); err != nil {
		t.Fatalf("creating admin: %v", err)
	}
	if err := d.UpdateLocalAdminPassword(ctx, "admin-mct", "newhash", true); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	got, _ := d.GetLocalAdmin(ctx, "admin-mct")
	if !got.MustChangePassword {
		t.Error("expected MustChangePassword=true after update with mustChange=true")
	}
}

// --- IDP: MFAProviderID non-nil branch in CreateIDP and scanIDP ---

// TestScanIDP_WithMFAProviderID covers the mfaProviderID.Valid branch in scanIDP
// and the MFAProviderID != nil branch in CreateIDP.
func TestScanIDP_WithMFAProviderID(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	if err := d.CreateMFAProvider(ctx, &MFAProviderRecord{
		ID: "mfa-idp-link", Name: "M", ProviderType: "duo", Enabled: true, ConfigJSON: "{}",
	}); err != nil {
		t.Fatalf("creating MFA provider: %v", err)
	}

	mfaID := "mfa-idp-link"
	if err := d.CreateIDP(ctx, &IdentityProviderRecord{
		ID:            "idp-with-mfa-link",
		FriendlyName:  "Test IDP",
		ProviderType:  "ad",
		ConfigJSON:    "{}",
		MFAProviderID: &mfaID,
	}); err != nil {
		t.Fatalf("creating IDP with MFAProviderID: %v", err)
	}

	got, err := d.GetIDP(ctx, "idp-with-mfa-link")
	if err != nil {
		t.Fatalf("getting IDP: %v", err)
	}
	if got.MFAProviderID == nil || *got.MFAProviderID != "mfa-idp-link" {
		t.Errorf("expected MFAProviderID=mfa-idp-link, got %v", got.MFAProviderID)
	}
}

// TestUpdateIDP_WithMFAProviderID covers the mfaProviderID != nil branch in UpdateIDP.
func TestUpdateIDP_WithMFAProviderID(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	if err := d.CreateMFAProvider(ctx, &MFAProviderRecord{
		ID: "mfa-for-upd", Name: "M", ProviderType: "duo", Enabled: true, ConfigJSON: "{}",
	}); err != nil {
		t.Fatalf("creating MFA provider: %v", err)
	}
	createTestIDP(t, d, "idp-upd-mfa")

	mfaID := "mfa-for-upd"
	if err := d.UpdateIDP(ctx, &IdentityProviderRecord{
		ID:            "idp-upd-mfa",
		FriendlyName:  "Updated",
		ProviderType:  "ad",
		ConfigJSON:    "{}",
		MFAProviderID: &mfaID,
	}); err != nil {
		t.Fatalf("updating IDP with MFAProviderID: %v", err)
	}

	got, _ := d.GetIDP(ctx, "idp-upd-mfa")
	if got.MFAProviderID == nil || *got.MFAProviderID != "mfa-for-upd" {
		t.Errorf("expected MFAProviderID set after update, got %v", got.MFAProviderID)
	}
}

// --- Malformed timestamp tests ---

// TestListLocalAdmins_MalformedUpdatedAt covers the time.Parse error for updated_at in ListLocalAdmins.
func TestListLocalAdmins_MalformedUpdatedAt(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()
	_, err := d.writer.ExecContext(ctx,
		`INSERT INTO local_admins (username, password_hash, must_change_password, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?)`,
		"bad-ua-list", "hash", 0, "2024-01-01T00:00:00Z", "NOT-A-DATE")
	if err != nil {
		t.Fatalf("inserting malformed row: %v", err)
	}
	_, err = d.ListLocalAdmins(ctx)
	if err == nil {
		t.Error("expected error for malformed updated_at in ListLocalAdmins, got nil")
	}
}

// TestScanIDP_MalformedCreatedAt covers the created_at parse error in scanIDP (via ListIDPs,
// which also covers the scanIDP error path in queryIDPs).
func TestScanIDP_MalformedCreatedAt(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()
	_, err := d.writer.ExecContext(ctx,
		`INSERT INTO identity_providers
		 (id, friendly_name, description, provider_type, enabled, logo_url, config_json, secret_blob, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"idp-bad-ca", "Test", "", "ad", 0, "", "{}", nil, "NOT-A-DATE", "2024-01-01T00:00:00Z")
	if err != nil {
		t.Fatalf("inserting malformed IDP: %v", err)
	}
	_, err = d.ListIDPs(ctx)
	if err == nil {
		t.Error("expected error for malformed IDP created_at, got nil")
	}
}

// TestScanIDP_MalformedUpdatedAt covers the updated_at parse error in scanIDP (via GetIDP).
func TestScanIDP_MalformedUpdatedAt(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()
	_, err := d.writer.ExecContext(ctx,
		`INSERT INTO identity_providers
		 (id, friendly_name, description, provider_type, enabled, logo_url, config_json, secret_blob, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"idp-bad-ua", "Test", "", "ad", 0, "", "{}", nil, "2024-01-01T00:00:00Z", "NOT-A-DATE")
	if err != nil {
		t.Fatalf("inserting malformed IDP: %v", err)
	}
	_, err = d.GetIDP(ctx, "idp-bad-ua")
	if err == nil {
		t.Error("expected error for malformed IDP updated_at, got nil")
	}
}

// TestScanAdminGroups_MalformedCreatedAt covers the time.Parse error in scanAdminGroups.
func TestScanAdminGroups_MalformedCreatedAt(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()
	createTestIDP(t, d, "idp-ag-bad")
	_, err := d.writer.ExecContext(ctx,
		`INSERT INTO admin_groups (idp_id, group_dn, description, created_at) VALUES (?, ?, ?, ?)`,
		"idp-ag-bad", "cn=bad,dc=example,dc=com", "desc", "NOT-A-DATE")
	if err != nil {
		t.Fatalf("inserting malformed admin group: %v", err)
	}
	_, err = d.ListAdminGroups(ctx)
	if err == nil {
		t.Error("expected error for malformed admin_groups created_at, got nil")
	}
}

// TestGetSMTPConfig_MalformedUpdatedAt covers the time.Parse error in GetSMTPConfig.
func TestGetSMTPConfig_MalformedUpdatedAt(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()
	_, err := d.writer.ExecContext(ctx,
		`INSERT INTO smtp_config (id, config_json, secret_blob, updated_at)
		 VALUES (1, '{}', NULL, 'NOT-A-DATE')
		 ON CONFLICT(id) DO UPDATE SET updated_at = excluded.updated_at`)
	if err != nil {
		t.Fatalf("inserting malformed smtp_config: %v", err)
	}
	_, err = d.GetSMTPConfig(ctx)
	if err == nil {
		t.Error("expected error for malformed smtp_config updated_at, got nil")
	}
}

// TestListEmailTemplates_MalformedUpdatedAt covers the time.Parse error in ListEmailTemplates.
func TestListEmailTemplates_MalformedUpdatedAt(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()
	_, err := d.writer.ExecContext(ctx,
		`INSERT INTO email_templates (template_type, subject, body_html, updated_at)
		 VALUES ('bad_ts_list_tmpl', 'Subject', '<p/>', 'NOT-A-DATE')`)
	if err != nil {
		t.Fatalf("inserting malformed email template: %v", err)
	}
	_, err = d.ListEmailTemplates(ctx)
	if err == nil {
		t.Error("expected error for malformed email_template updated_at in ListEmailTemplates, got nil")
	}
}

// TestGetEmailTemplate_MalformedUpdatedAt covers the time.Parse error in GetEmailTemplate.
func TestGetEmailTemplate_MalformedUpdatedAt(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()
	_, err := d.writer.ExecContext(ctx,
		`INSERT INTO email_templates (template_type, subject, body_html, updated_at)
		 VALUES ('bad_ts_get_tmpl', 'Subject', '<p/>', 'NOT-A-DATE')`)
	if err != nil {
		t.Fatalf("inserting malformed email template: %v", err)
	}
	_, err = d.GetEmailTemplate(ctx, "bad_ts_get_tmpl")
	if err == nil {
		t.Error("expected error for malformed email_template updated_at in GetEmailTemplate, got nil")
	}
}

// TestGetExpirationConfig_MalformedUpdatedAt covers the time.Parse error in GetExpirationConfig.
func TestGetExpirationConfig_MalformedUpdatedAt(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()
	createTestIDP(t, d, "idp-exp-bad-ts")
	if err := d.SaveExpirationConfig(ctx, &ExpirationConfig{
		IDPID: "idp-exp-bad-ts", Enabled: true, CronSchedule: "0 0 * * *", DaysBeforeExpiration: 7,
	}); err != nil {
		t.Fatalf("saving expiration config: %v", err)
	}
	if _, err := d.writer.ExecContext(ctx,
		`UPDATE idp_expiration_config SET updated_at = 'NOT-A-DATE' WHERE idp_id = ?`, "idp-exp-bad-ts"); err != nil {
		t.Fatalf("updating expiration config timestamp: %v", err)
	}
	_, err := d.GetExpirationConfig(ctx, "idp-exp-bad-ts")
	if err == nil {
		t.Error("expected error for malformed expiration config updated_at, got nil")
	}
}

// TestListEnabledExpirationConfigs_MalformedUpdatedAt covers the time.Parse error
// in ListEnabledExpirationConfigs.
func TestListEnabledExpirationConfigs_MalformedUpdatedAt(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()
	createTestIDP(t, d, "idp-lec-bad-ts")
	if err := d.SaveExpirationConfig(ctx, &ExpirationConfig{
		IDPID: "idp-lec-bad-ts", Enabled: true, CronSchedule: "0 0 * * *", DaysBeforeExpiration: 7,
	}); err != nil {
		t.Fatalf("saving expiration config: %v", err)
	}
	if _, err := d.writer.ExecContext(ctx,
		`UPDATE idp_expiration_config SET updated_at = 'NOT-A-DATE' WHERE idp_id = ?`, "idp-lec-bad-ts"); err != nil {
		t.Fatalf("updating expiration config timestamp: %v", err)
	}
	_, err := d.ListEnabledExpirationConfigs(ctx)
	if err == nil {
		t.Error("expected error for malformed expiration config updated_at in ListEnabledExpirationConfigs, got nil")
	}
}

// TestScanMFAProvider_MalformedCreatedAt covers the created_at parse error in scanMFAProvider.
// Calling ListMFAProviders also covers the scanMFAProvider error path in queryMFAProviders.
func TestScanMFAProvider_MalformedCreatedAt(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()
	_, err := d.writer.ExecContext(ctx,
		`INSERT INTO mfa_providers (id, name, provider_type, enabled, config_json, secret_blob, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		"mfa-bad-ca", "M", "duo", 0, "{}", nil, "NOT-A-DATE", "2024-01-01T00:00:00Z")
	if err != nil {
		t.Fatalf("inserting malformed MFA provider: %v", err)
	}
	_, err = d.ListMFAProviders(ctx)
	if err == nil {
		t.Error("expected error for malformed MFA provider created_at, got nil")
	}
}

// TestScanMFAProvider_MalformedUpdatedAt covers the updated_at parse error in scanMFAProvider.
func TestScanMFAProvider_MalformedUpdatedAt(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()
	_, err := d.writer.ExecContext(ctx,
		`INSERT INTO mfa_providers (id, name, provider_type, enabled, config_json, secret_blob, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		"mfa-bad-ua", "M", "duo", 0, "{}", nil, "2024-01-01T00:00:00Z", "NOT-A-DATE")
	if err != nil {
		t.Fatalf("inserting malformed MFA provider: %v", err)
	}
	_, err = d.GetMFAProvider(ctx, "mfa-bad-ua")
	if err == nil {
		t.Error("expected error for malformed MFA provider updated_at, got nil")
	}
}

// TestScanMapping_MalformedLinkedAt covers the linked_at parse error in scanMapping (via GetMapping).
func TestScanMapping_MalformedLinkedAt(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()
	createTestIDP(t, d, "idp-sm-a")
	createTestIDP(t, d, "idp-sm-b")
	_, err := d.writer.ExecContext(ctx,
		`INSERT INTO user_idp_mappings (auth_provider_id, auth_username, target_idp_id, target_account_dn, link_type, linked_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		"idp-sm-a", "bad-linked", "idp-sm-b", "cn=bad,dc=b", "auto", "NOT-A-DATE")
	if err != nil {
		t.Fatalf("inserting malformed mapping: %v", err)
	}
	_, err = d.GetMapping(ctx, "idp-sm-a", "bad-linked", "idp-sm-b")
	if err == nil {
		t.Error("expected error for malformed linked_at in scanMapping, got nil")
	}
}

// TestScanMapping_MalformedVerifiedAt covers the verified_at parse error in scanMapping (via GetMapping).
func TestScanMapping_MalformedVerifiedAt(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()
	createTestIDP(t, d, "idp-smv-a")
	createTestIDP(t, d, "idp-smv-b")
	_, err := d.writer.ExecContext(ctx,
		`INSERT INTO user_idp_mappings (auth_provider_id, auth_username, target_idp_id, target_account_dn, link_type, linked_at, verified_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"idp-smv-a", "bad-verified", "idp-smv-b", "cn=bv,dc=b", "auto", "2024-01-01T00:00:00Z", "NOT-A-DATE")
	if err != nil {
		t.Fatalf("inserting malformed mapping: %v", err)
	}
	_, err = d.GetMapping(ctx, "idp-smv-a", "bad-verified", "idp-smv-b")
	if err == nil {
		t.Error("expected error for malformed verified_at in scanMapping, got nil")
	}
}

// TestListMappings_MalformedLinkedAt covers the linked_at parse error in ListMappings.
func TestListMappings_MalformedLinkedAt(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()
	createTestIDP(t, d, "idp-lml-a")
	createTestIDP(t, d, "idp-lml-b")
	_, err := d.writer.ExecContext(ctx,
		`INSERT INTO user_idp_mappings (auth_provider_id, auth_username, target_idp_id, target_account_dn, link_type, linked_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		"idp-lml-a", "lml-user", "idp-lml-b", "cn=lml,dc=b", "auto", "NOT-A-DATE")
	if err != nil {
		t.Fatalf("inserting malformed mapping: %v", err)
	}
	_, err = d.ListMappings(ctx, "idp-lml-a", "lml-user")
	if err == nil {
		t.Error("expected error for malformed linked_at in ListMappings, got nil")
	}
}

// TestListMappings_MalformedVerifiedAt covers the verified_at parse error in ListMappings.
func TestListMappings_MalformedVerifiedAt(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()
	createTestIDP(t, d, "idp-lmv-a")
	createTestIDP(t, d, "idp-lmv-b")
	_, err := d.writer.ExecContext(ctx,
		`INSERT INTO user_idp_mappings (auth_provider_id, auth_username, target_idp_id, target_account_dn, link_type, linked_at, verified_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"idp-lmv-a", "lmv-user", "idp-lmv-b", "cn=lmv,dc=b", "auto", "2024-01-01T00:00:00Z", "NOT-A-DATE")
	if err != nil {
		t.Fatalf("inserting malformed mapping: %v", err)
	}
	_, err = d.ListMappings(ctx, "idp-lmv-a", "lmv-user")
	if err == nil {
		t.Error("expected error for malformed verified_at in ListMappings, got nil")
	}
}

// TestSearchMappings_MalformedLinkedAt covers the linked_at parse error in SearchMappings.
func TestSearchMappings_MalformedLinkedAt(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()
	createTestIDP(t, d, "idp-sml-a")
	createTestIDP(t, d, "idp-sml-b")
	_, err := d.writer.ExecContext(ctx,
		`INSERT INTO user_idp_mappings (auth_provider_id, auth_username, target_idp_id, target_account_dn, link_type, linked_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		"idp-sml-a", "sml-user", "idp-sml-b", "cn=sml,dc=b", "auto", "NOT-A-DATE")
	if err != nil {
		t.Fatalf("inserting malformed mapping: %v", err)
	}
	_, _, err = d.SearchMappings(ctx, MappingSearchFilter{ProviderID: "idp-sml-a", Username: "sml-user", Limit: 100})
	if err == nil {
		t.Error("expected error for malformed linked_at in SearchMappings, got nil")
	}
}

// TestSearchMappings_MalformedVerifiedAt covers the verified_at parse error in SearchMappings.
func TestSearchMappings_MalformedVerifiedAt(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()
	createTestIDP(t, d, "idp-smv2-a")
	createTestIDP(t, d, "idp-smv2-b")
	_, err := d.writer.ExecContext(ctx,
		`INSERT INTO user_idp_mappings (auth_provider_id, auth_username, target_idp_id, target_account_dn, link_type, linked_at, verified_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"idp-smv2-a", "smv2-user", "idp-smv2-b", "cn=smv2,dc=b", "auto", "2024-01-01T00:00:00Z", "NOT-A-DATE")
	if err != nil {
		t.Fatalf("inserting malformed mapping: %v", err)
	}
	_, _, err = d.SearchMappings(ctx, MappingSearchFilter{ProviderID: "idp-smv2-a", Username: "smv2-user", Limit: 100})
	if err == nil {
		t.Error("expected error for malformed verified_at in SearchMappings, got nil")
	}
}

// TestListAllMappings_MalformedLinkedAt covers the linked_at parse error in ListAllMappings.
func TestListAllMappings_MalformedLinkedAt(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()
	createTestIDP(t, d, "idp-laml-a")
	createTestIDP(t, d, "idp-laml-b")
	_, err := d.writer.ExecContext(ctx,
		`INSERT INTO user_idp_mappings (auth_provider_id, auth_username, target_idp_id, target_account_dn, link_type, linked_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		"idp-laml-a", "laml-user", "idp-laml-b", "cn=laml,dc=b", "auto", "NOT-A-DATE")
	if err != nil {
		t.Fatalf("inserting malformed mapping: %v", err)
	}
	_, err = d.ListAllMappings(ctx)
	if err == nil {
		t.Error("expected error for malformed linked_at in ListAllMappings, got nil")
	}
}

// TestListAllMappings_MalformedVerifiedAt covers the verified_at parse error in ListAllMappings.
func TestListAllMappings_MalformedVerifiedAt(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()
	createTestIDP(t, d, "idp-lamv-a")
	createTestIDP(t, d, "idp-lamv-b")
	_, err := d.writer.ExecContext(ctx,
		`INSERT INTO user_idp_mappings (auth_provider_id, auth_username, target_idp_id, target_account_dn, link_type, linked_at, verified_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"idp-lamv-a", "lamv-user", "idp-lamv-b", "cn=lamv,dc=b", "auto", "2024-01-01T00:00:00Z", "NOT-A-DATE")
	if err != nil {
		t.Fatalf("inserting malformed mapping: %v", err)
	}
	_, err = d.ListAllMappings(ctx)
	if err == nil {
		t.Error("expected error for malformed verified_at in ListAllMappings, got nil")
	}
}

// TestListAudit_MalformedTimestamp covers the parse audit timestamp error path in ListAudit.
func TestListAudit_MalformedTimestamp(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()
	_, err := d.writer.ExecContext(ctx,
		`INSERT INTO audit_log (username, source_ip, action, result, timestamp)
		 VALUES (?, ?, ?, ?, ?)`,
		"user", "1.1.1.1", "login", "success", "NOT-A-DATE")
	if err != nil {
		t.Fatalf("inserting malformed audit entry: %v", err)
	}
	_, _, err = d.ListAudit(ctx, AuditFilter{Limit: 10})
	if err == nil {
		t.Error("expected error for malformed audit timestamp, got nil")
	}
}

// --- Migration tests ---

// TestMigrationsComplete_False verifies MigrationsComplete returns false when
// a migration record is deleted.
func TestMigrationsComplete_False(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()
	if _, err := d.writer.ExecContext(ctx, `DELETE FROM schema_migrations WHERE version = 1`); err != nil {
		t.Fatalf("deleting migration record: %v", err)
	}
	complete, err := d.MigrationsComplete(ctx)
	if err != nil {
		t.Fatalf("MigrationsComplete error: %v", err)
	}
	if complete {
		t.Error("expected MigrationsComplete=false after deleting a migration record")
	}
}

// TestMigrate_WriterError covers the CREATE TABLE error path in Migrate.
func TestMigrate_WriterError(t *testing.T) {
	d, err := OpenMemory()
	if err != nil {
		t.Fatalf("opening memory db: %v", err)
	}
	defer d.Close()
	d.writer.Close()
	if err := d.Migrate(context.Background()); err == nil {
		t.Error("expected error when migrating with closed writer, got nil")
	}
}

// TestListAudit_LimitClamped covers the limit > 500 clamping branch in ListAudit.
func TestListAudit_LimitClamped(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	// Insert one entry so there is something to query.
	_ = d.AppendAudit(ctx, &AuditEntry{
		Username: "u", SourceIP: "1.1.1.1",
		Action: "login", Result: "success",
	})

	// Pass limit > 500; the function should clamp it to 500 and not error.
	entries, total, err := d.ListAudit(ctx, AuditFilter{Limit: 600})
	if err != nil {
		t.Fatalf("ListAudit with limit>500: %v", err)
	}
	if total != 1 {
		t.Errorf("expected total=1, got %d", total)
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 entry, got %d", len(entries))
	}
}

// TestListAudit_NegativeOffset covers the offset < 0 clamping branch in ListAudit.
func TestListAudit_NegativeOffset(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	// Insert one entry so there is something to query.
	_ = d.AppendAudit(ctx, &AuditEntry{
		Username: "u", SourceIP: "1.1.1.1",
		Action: "login", Result: "success",
	})

	// Pass a negative offset; the function should clamp it to 0 and not error.
	entries, total, err := d.ListAudit(ctx, AuditFilter{Limit: 50, Offset: -5})
	if err != nil {
		t.Fatalf("ListAudit with negative offset: %v", err)
	}
	if total != 1 {
		t.Errorf("expected total=1, got %d", total)
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 entry, got %d", len(entries))
	}
}

func TestGetMFALoginRequired_Default(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	// Default value should be false (mfa_settings row has require_mfa_on_login=0).
	required, err := d.GetMFALoginRequired(ctx)
	if err != nil {
		t.Fatalf("GetMFALoginRequired: %v", err)
	}
	if required {
		t.Error("expected default MFA login required = false")
	}
}

func TestSetAndGetMFALoginRequired(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	// Enable MFA login requirement.
	if err := d.SetMFALoginRequired(ctx, true); err != nil {
		t.Fatalf("SetMFALoginRequired(true): %v", err)
	}
	required, err := d.GetMFALoginRequired(ctx)
	if err != nil {
		t.Fatalf("GetMFALoginRequired after set true: %v", err)
	}
	if !required {
		t.Error("expected MFA login required = true after setting")
	}

	// Disable again.
	if err := d.SetMFALoginRequired(ctx, false); err != nil {
		t.Fatalf("SetMFALoginRequired(false): %v", err)
	}
	required, err = d.GetMFALoginRequired(ctx)
	if err != nil {
		t.Fatalf("GetMFALoginRequired after set false: %v", err)
	}
	if required {
		t.Error("expected MFA login required = false after disabling")
	}
}

func TestSetMFALoginRequired_WriterError(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()
	d.writer.Close()
	if err := d.SetMFALoginRequired(ctx, true); err == nil {
		t.Error("expected error when writer is closed")
	}
}

func TestGetMFALoginRequired_ReaderError(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()
	d.reader.Close()
	_, err := d.GetMFALoginRequired(ctx)
	if err == nil {
		t.Error("expected error when reader is closed")
	}
}

func TestCorrelationWarning_SetListDelete(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	w := &CorrelationWarning{
		AuthUsername: "jdoe",
		TargetIDPID:  "corp-ad",
		WarningType:  "ambiguous_match",
		Message:      "multiple entries found",
	}

	if err := d.SetCorrelationWarning(ctx, w); err != nil {
		t.Fatalf("SetCorrelationWarning: %v", err)
	}

	warnings, err := d.ListCorrelationWarnings(ctx, "jdoe")
	if err != nil {
		t.Fatalf("ListCorrelationWarnings: %v", err)
	}
	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d", len(warnings))
	}
	if warnings[0].WarningType != "ambiguous_match" {
		t.Errorf("expected warning type 'ambiguous_match', got %q", warnings[0].WarningType)
	}

	// Upsert updates the existing record.
	w.Message = "updated message"
	if err := d.SetCorrelationWarning(ctx, w); err != nil {
		t.Fatalf("SetCorrelationWarning (upsert): %v", err)
	}

	// Delete the warning.
	if err := d.DeleteCorrelationWarning(ctx, "jdoe", "corp-ad"); err != nil {
		t.Fatalf("DeleteCorrelationWarning: %v", err)
	}

	warnings, err = d.ListCorrelationWarnings(ctx, "jdoe")
	if err != nil {
		t.Fatalf("ListCorrelationWarnings after delete: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("expected 0 warnings after delete, got %d", len(warnings))
	}
}

func TestCorrelationWarning_SetError(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()
	d.writer.Close()
	err := d.SetCorrelationWarning(ctx, &CorrelationWarning{
		AuthUsername: "u", TargetIDPID: "idp", WarningType: "t",
	})
	if err == nil {
		t.Error("expected error when writer is closed")
	}
}

func TestCorrelationWarning_DeleteError(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()
	d.writer.Close()
	if err := d.DeleteCorrelationWarning(ctx, "u", "idp"); err == nil {
		t.Error("expected error when writer is closed")
	}
}

func TestCorrelationWarning_ListError(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()
	d.reader.Close()
	_, err := d.ListCorrelationWarnings(ctx, "u")
	if err == nil {
		t.Error("expected error when reader is closed")
	}
}

// --- Coverage: MigrationsComplete reader error ---

// TestMigrationsComplete_ReaderError covers the reader QueryRowContext error path in MigrationsComplete.
func TestMigrationsComplete_ReaderError(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()
	d.reader.Close()
	_, err := d.MigrationsComplete(ctx)
	if err == nil {
		t.Error("expected error when reader is closed, got nil")
	}
}

// --- Coverage: ListCorrelationWarnings malformed created_at ---

// TestListCorrelationWarnings_MalformedCreatedAt covers the time.Parse error in ListCorrelationWarnings.
func TestListCorrelationWarnings_MalformedCreatedAt(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()
	_, err := d.writer.ExecContext(ctx,
		`INSERT INTO correlation_warnings (auth_username, target_idp_id, warning_type, message, created_at)
		 VALUES (?, ?, ?, ?, ?)`,
		"bad-ts-cw-user", "any-idp", "ambiguous_match", "test msg", "NOT-A-DATE")
	if err != nil {
		t.Fatalf("inserting malformed correlation warning: %v", err)
	}
	_, err = d.ListCorrelationWarnings(ctx, "bad-ts-cw-user")
	if err == nil {
		t.Error("expected error for malformed created_at in ListCorrelationWarnings, got nil")
	}
}

// --- Coverage: GetMFAProviderForIDP scan error paths ---

// TestGetMFAProviderForIDP_DirectScanError covers the non-ErrNoRows error path in the direct
// provider query of GetMFAProviderForIDP (the !errors.Is(err, sql.ErrNoRows) branch).
func TestGetMFAProviderForIDP_DirectScanError(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	// Insert an enabled MFA provider with a malformed created_at timestamp.
	_, err := d.writer.ExecContext(ctx,
		`INSERT INTO mfa_providers (id, name, provider_type, enabled, config_json, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"mfa-bad-direct-ts", "Bad Direct MFA", "duo", 1, "{}", "NOT-A-DATE", "2024-01-01T00:00:00Z")
	if err != nil {
		t.Fatalf("inserting malformed MFA provider: %v", err)
	}

	// Create an IDP that directly references this MFA provider.
	// identity_providers.mfa_provider_id has no FK constraint, so this succeeds.
	mfaID := "mfa-bad-direct-ts"
	if err := d.CreateIDP(ctx, &IdentityProviderRecord{
		ID:            "idp-bad-direct-mfa-ts",
		FriendlyName:  "Test IDP Direct Bad TS",
		ProviderType:  "ad",
		ConfigJSON:    "{}",
		MFAProviderID: &mfaID,
	}); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	_, err = d.GetMFAProviderForIDP(ctx, "idp-bad-direct-mfa-ts")
	if err == nil {
		t.Error("expected error for malformed MFA provider created_at in direct scan, got nil")
	}
}

// TestGetMFAProviderForIDP_DefaultScanError covers the non-ErrNoRows error path in the default
// provider query of GetMFAProviderForIDP (the second !errors.Is(err, sql.ErrNoRows) branch).
func TestGetMFAProviderForIDP_DefaultScanError(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	// Create a normal IDP with no direct mfa_provider_id.
	createTestIDP(t, d, "idp-no-direct-mfa-defts")

	// Insert an enabled MFA provider with a malformed updated_at timestamp.
	_, err := d.writer.ExecContext(ctx,
		`INSERT INTO mfa_providers (id, name, provider_type, enabled, config_json, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"mfa-bad-default-ts", "Bad Default MFA", "duo", 1, "{}", "2024-01-01T00:00:00Z", "NOT-A-DATE")
	if err != nil {
		t.Fatalf("inserting malformed MFA provider: %v", err)
	}

	// Point mfa_settings default to this bad-timestamp provider.
	if _, err = d.writer.ExecContext(ctx,
		`UPDATE mfa_settings SET default_mfa_provider_id = ? WHERE id = 1`,
		"mfa-bad-default-ts"); err != nil {
		t.Fatalf("setting default MFA provider: %v", err)
	}

	_, err = d.GetMFAProviderForIDP(ctx, "idp-no-direct-mfa-defts")
	if err == nil {
		t.Error("expected error for malformed default MFA provider updated_at, got nil")
	}
}

// --- Coverage: GetMFALoginRequired sql.ErrNoRows path ---

// TestGetMFALoginRequired_NoSettingsRow covers the sql.ErrNoRows path in GetMFALoginRequired
// (when the mfa_settings singleton row has been deleted).
func TestGetMFALoginRequired_NoSettingsRow(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	if _, err := d.writer.ExecContext(ctx, `DELETE FROM mfa_settings WHERE id = 1`); err != nil {
		t.Fatalf("deleting mfa_settings row: %v", err)
	}

	required, err := d.GetMFALoginRequired(ctx)
	if err != nil {
		t.Fatalf("expected nil error for ErrNoRows path, got %v", err)
	}
	if required {
		t.Error("expected required=false when no mfa_settings row")
	}
}

// --- Coverage: SetAttributeMappings stmt.ExecContext FK constraint error ---

// TestSetAttributeMappings_FKConstraintError covers the stmt.ExecContext error path in
// SetAttributeMappings when the FK constraint on idp_id is violated.
func TestSetAttributeMappings_FKConstraintError(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	// "nonexistent-fk-idp" does not exist in identity_providers, so the INSERT
	// within the transaction will fail with a FK constraint violation.
	err := d.SetAttributeMappings(ctx, "nonexistent-fk-idp", []AttributeMapping{
		{IDPID: "nonexistent-fk-idp", CanonicalName: "email", DirectoryAttr: "mail"},
	})
	if err == nil {
		t.Error("expected error for FK constraint violation in SetAttributeMappings, got nil")
	}
}

// --- Coverage: SaveExpirationFilters stmt.ExecContext FK constraint error ---

// TestSaveExpirationFilters_FKConstraintError covers the stmt.ExecContext error path in
// SaveExpirationFilters when the FK constraint on idp_id is violated.
func TestSaveExpirationFilters_FKConstraintError(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	// "nonexistent-fk-idp2" does not exist in identity_providers.
	err := d.SaveExpirationFilters(ctx, "nonexistent-fk-idp2", []ExpirationFilter{
		{Attribute: "department", Pattern: "Engineering", Description: "test"},
	})
	if err == nil {
		t.Error("expected error for FK constraint violation in SaveExpirationFilters, got nil")
	}
}

// --- Coverage: session_store ExecContext DB error paths ---

// closedWriterDB opens a memory DB, closes the writer connection, and returns
// the broken DB. Callers must not close it again (writer is already closed).
func closedWriterDB(t *testing.T) *DB {
	t.Helper()
	d := newTestDB(t)
	d.writer.Close() // force all subsequent writer ExecContext calls to fail
	return d
}

func TestTouchSession_DBError(t *testing.T) {
	d := closedWriterDB(t)
	err := d.TouchSession(context.Background(), "any-id", time.Now().Add(time.Hour).UTC())
	if err == nil {
		t.Error("expected error from TouchSession with closed writer, got nil")
	}
}

func TestUpdateSessionFlash_DBError(t *testing.T) {
	d := closedWriterDB(t)
	err := d.UpdateSessionFlash(context.Background(), "any-id", `{}`)
	if err == nil {
		t.Error("expected error from UpdateSessionFlash with closed writer, got nil")
	}
}

func TestUpdateSessionMustChangePassword_DBError(t *testing.T) {
	d := closedWriterDB(t)
	err := d.UpdateSessionMustChangePassword(context.Background(), "any-id", true)
	if err == nil {
		t.Error("expected error from UpdateSessionMustChangePassword with closed writer, got nil")
	}
}

func TestUpdateSessionMFA_DBError(t *testing.T) {
	d := closedWriterDB(t)
	err := d.UpdateSessionMFA(context.Background(), "any-id", true, "state")
	if err == nil {
		t.Error("expected error from UpdateSessionMFA with closed writer, got nil")
	}
}

func TestUpdateSessionMFAAttempts_DBError(t *testing.T) {
	d := closedWriterDB(t)
	err := d.UpdateSessionMFAAttempts(context.Background(), "any-id", 1)
	if err == nil {
		t.Error("expected error from UpdateSessionMFAAttempts with closed writer, got nil")
	}
}

// TestListAudit_ZeroLimit covers the limit <= 0 → default 50 branch in ListAudit.
func TestListAudit_ZeroLimit(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	_ = d.AppendAudit(ctx, &AuditEntry{
		Username: "u", SourceIP: "1.1.1.1",
		Action: "login", Result: "success",
	})

	// Limit: 0 should be treated as the default (50) inside ListAudit.
	entries, total, err := d.ListAudit(ctx, AuditFilter{Limit: 0})
	if err != nil {
		t.Fatalf("ListAudit with zero limit: %v", err)
	}
	if total != 1 {
		t.Errorf("expected total=1, got %d", total)
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 entry, got %d", len(entries))
	}
}
