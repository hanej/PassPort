package db

import (
	"context"
	"strings"
	"testing"
)

func TestGetReportConfig_NotFound(t *testing.T) {
	d := newTestDB(t)
	cfg, err := d.GetReportConfig(context.Background(), "nonexistent", ReportTypeExpiration)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg != nil {
		t.Error("expected nil config for missing key")
	}
}

func TestSaveAndGetReportConfig(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	if err := d.CreateIDP(ctx, &IdentityProviderRecord{
		ID: "corp-ad", FriendlyName: "Corp AD", ProviderType: "ad",
		Enabled: true, ConfigJSON: "{}",
	}); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	cfg := &ReportConfig{
		IDPID:                "corp-ad",
		ReportType:           ReportTypeExpiration,
		Enabled:              true,
		CronSchedule:         "0 7 * * 1",
		DaysBeforeExpiration: 14,
		Recipients:           "admin@example.com",
		ExcludeDisabled:      true,
	}
	if err := d.SaveReportConfig(ctx, cfg); err != nil {
		t.Fatalf("saving config: %v", err)
	}

	got, err := d.GetReportConfig(ctx, "corp-ad", ReportTypeExpiration)
	if err != nil {
		t.Fatalf("getting config: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil config")
	}
	if !got.Enabled {
		t.Error("expected enabled=true")
	}
	if got.CronSchedule != "0 7 * * 1" {
		t.Errorf("unexpected schedule: %s", got.CronSchedule)
	}
	if got.DaysBeforeExpiration != 14 {
		t.Errorf("unexpected days: %d", got.DaysBeforeExpiration)
	}
	if got.Recipients != "admin@example.com" {
		t.Errorf("unexpected recipients: %s", got.Recipients)
	}
	if !got.ExcludeDisabled {
		t.Error("expected exclude_disabled=true")
	}
	if got.UpdatedAt.IsZero() {
		t.Error("expected non-zero updated_at")
	}
}

func TestSaveReportConfig_Update(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	if err := d.CreateIDP(ctx, &IdentityProviderRecord{
		ID: "corp-ad", FriendlyName: "Corp AD", ProviderType: "ad",
		Enabled: true, ConfigJSON: "{}",
	}); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	cfg := &ReportConfig{
		IDPID: "corp-ad", ReportType: ReportTypeExpiration,
		Enabled: true, CronSchedule: "0 0 * * *", DaysBeforeExpiration: 7,
	}
	if err := d.SaveReportConfig(ctx, cfg); err != nil {
		t.Fatalf("initial save: %v", err)
	}

	cfg.DaysBeforeExpiration = 21
	cfg.Recipients = "new@example.com"
	cfg.Enabled = false
	if err := d.SaveReportConfig(ctx, cfg); err != nil {
		t.Fatalf("update save: %v", err)
	}

	got, err := d.GetReportConfig(ctx, "corp-ad", ReportTypeExpiration)
	if err != nil || got == nil {
		t.Fatalf("getting config after update: err=%v, cfg=%v", err, got)
	}
	if got.DaysBeforeExpiration != 21 {
		t.Errorf("expected days=21, got %d", got.DaysBeforeExpiration)
	}
	if got.Enabled {
		t.Error("expected enabled=false after update")
	}
	if got.Recipients != "new@example.com" {
		t.Errorf("unexpected recipients: %s", got.Recipients)
	}
}

func TestSaveReportConfig_ExcludeDisabledFalse(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	if err := d.CreateIDP(ctx, &IdentityProviderRecord{
		ID: "freeipa", FriendlyName: "FreeIPA", ProviderType: "freeipa",
		Enabled: true, ConfigJSON: "{}",
	}); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	cfg := &ReportConfig{
		IDPID: "freeipa", ReportType: ReportTypeExpired,
		Enabled: false, CronSchedule: "0 0 * * 0", ExcludeDisabled: false,
	}
	if err := d.SaveReportConfig(ctx, cfg); err != nil {
		t.Fatalf("saving config: %v", err)
	}

	got, err := d.GetReportConfig(ctx, "freeipa", ReportTypeExpired)
	if err != nil || got == nil {
		t.Fatalf("got err=%v, cfg=%v", err, got)
	}
	if got.ExcludeDisabled {
		t.Error("expected exclude_disabled=false")
	}
}

func TestListReportFilters_Empty(t *testing.T) {
	d := newTestDB(t)
	filters, err := d.ListReportFilters(context.Background(), "nonexistent", ReportTypeExpiration)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(filters) != 0 {
		t.Errorf("expected 0 filters, got %d", len(filters))
	}
}

func TestSaveAndListReportFilters(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	if err := d.CreateIDP(ctx, &IdentityProviderRecord{
		ID: "corp-ad", FriendlyName: "Corp AD", ProviderType: "ad",
		Enabled: true, ConfigJSON: "{}",
	}); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	filters := []ReportFilter{
		{IDPID: "corp-ad", ReportType: ReportTypeExpiration, Attribute: "dn", Pattern: "^ou=Service", Description: "Exclude service accounts"},
		{IDPID: "corp-ad", ReportType: ReportTypeExpiration, Attribute: "department", Pattern: "IT", Description: "Exclude IT dept"},
	}
	if err := d.SaveReportFilters(ctx, "corp-ad", ReportTypeExpiration, filters); err != nil {
		t.Fatalf("saving filters: %v", err)
	}

	got, err := d.ListReportFilters(ctx, "corp-ad", ReportTypeExpiration)
	if err != nil {
		t.Fatalf("listing filters: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 filters, got %d", len(got))
	}
	if got[0].Attribute != "dn" {
		t.Errorf("expected attribute 'dn', got %s", got[0].Attribute)
	}
	if got[1].Attribute != "department" {
		t.Errorf("expected attribute 'department', got %s", got[1].Attribute)
	}
	if got[0].Description != "Exclude service accounts" {
		t.Errorf("unexpected description: %s", got[0].Description)
	}
	// IDs should be non-zero.
	if got[0].ID == 0 {
		t.Error("expected non-zero ID for filter")
	}
}

func TestSaveReportFilters_Replace(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	if err := d.CreateIDP(ctx, &IdentityProviderRecord{
		ID: "corp-ad", FriendlyName: "Corp AD", ProviderType: "ad",
		Enabled: true, ConfigJSON: "{}",
	}); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	if err := d.SaveReportFilters(ctx, "corp-ad", ReportTypeExpiration, []ReportFilter{
		{IDPID: "corp-ad", ReportType: ReportTypeExpiration, Attribute: "dn", Pattern: "old"},
	}); err != nil {
		t.Fatalf("initial save: %v", err)
	}

	if err := d.SaveReportFilters(ctx, "corp-ad", ReportTypeExpiration, []ReportFilter{
		{IDPID: "corp-ad", ReportType: ReportTypeExpiration, Attribute: "department", Pattern: "new"},
	}); err != nil {
		t.Fatalf("replace save: %v", err)
	}

	got, err := d.ListReportFilters(ctx, "corp-ad", ReportTypeExpiration)
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	if len(got) != 1 || got[0].Attribute != "department" {
		t.Errorf("expected 1 filter with attribute 'department', got: %v", got)
	}
}

func TestSaveReportFilters_ClearAll(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	if err := d.CreateIDP(ctx, &IdentityProviderRecord{
		ID: "corp-ad", FriendlyName: "Corp AD", ProviderType: "ad",
		Enabled: true, ConfigJSON: "{}",
	}); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	if err := d.SaveReportFilters(ctx, "corp-ad", ReportTypeExpiration, []ReportFilter{
		{IDPID: "corp-ad", ReportType: ReportTypeExpiration, Attribute: "dn", Pattern: "test"},
	}); err != nil {
		t.Fatalf("initial save: %v", err)
	}

	if err := d.SaveReportFilters(ctx, "corp-ad", ReportTypeExpiration, nil); err != nil {
		t.Fatalf("clearing filters: %v", err)
	}

	got, err := d.ListReportFilters(ctx, "corp-ad", ReportTypeExpiration)
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0 filters after clear, got %d", len(got))
	}
}

func TestListEnabledReportConfigs(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	for _, id := range []string{"idp1", "idp2", "idp3"} {
		if err := d.CreateIDP(ctx, &IdentityProviderRecord{
			ID: id, FriendlyName: id, ProviderType: "ad",
			Enabled: true, ConfigJSON: "{}",
		}); err != nil {
			t.Fatalf("creating IDP %s: %v", id, err)
		}
	}

	if err := d.SaveReportConfig(ctx, &ReportConfig{
		IDPID: "idp1", ReportType: ReportTypeExpiration, Enabled: true, CronSchedule: "0 0 * * *",
	}); err != nil {
		t.Fatalf("saving config idp1: %v", err)
	}
	if err := d.SaveReportConfig(ctx, &ReportConfig{
		IDPID: "idp2", ReportType: ReportTypeExpiration, Enabled: false, CronSchedule: "0 0 * * *",
	}); err != nil {
		t.Fatalf("saving config idp2: %v", err)
	}
	if err := d.SaveReportConfig(ctx, &ReportConfig{
		IDPID: "idp3", ReportType: ReportTypeExpired, Enabled: true, CronSchedule: "0 0 * * *",
	}); err != nil {
		t.Fatalf("saving config idp3: %v", err)
	}

	got, err := d.ListEnabledReportConfigs(ctx)
	if err != nil {
		t.Fatalf("listing enabled configs: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("expected 2 enabled configs, got %d", len(got))
	}
}

func TestListEnabledReportConfigs_Empty(t *testing.T) {
	d := newTestDB(t)
	got, err := d.ListEnabledReportConfigs(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0, got %d", len(got))
	}
}

func TestListReportConfigsForIDP(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	if err := d.CreateIDP(ctx, &IdentityProviderRecord{
		ID: "corp-ad", FriendlyName: "Corp AD", ProviderType: "ad",
		Enabled: true, ConfigJSON: "{}",
	}); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	if err := d.SaveReportConfig(ctx, &ReportConfig{
		IDPID: "corp-ad", ReportType: ReportTypeExpiration, Enabled: true, CronSchedule: "0 0 * * *",
	}); err != nil {
		t.Fatalf("saving expiration config: %v", err)
	}
	if err := d.SaveReportConfig(ctx, &ReportConfig{
		IDPID: "corp-ad", ReportType: ReportTypeExpired, Enabled: false, CronSchedule: "0 1 * * *",
	}); err != nil {
		t.Fatalf("saving expired config: %v", err)
	}

	got, err := d.ListReportConfigsForIDP(ctx, "corp-ad")
	if err != nil {
		t.Fatalf("listing configs: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 configs, got %d", len(got))
	}
	// ORDER BY report_type: "expiration" < "expired" alphabetically ('a' < 'e' at index 5).
	if got[0].ReportType != ReportTypeExpiration {
		t.Errorf("expected first type 'expiration', got %s", got[0].ReportType)
	}
	if got[1].ReportType != ReportTypeExpired {
		t.Errorf("expected second type 'expired', got %s", got[1].ReportType)
	}
}

func TestListReportConfigsForIDP_Empty(t *testing.T) {
	d := newTestDB(t)
	got, err := d.ListReportConfigsForIDP(context.Background(), "nonexistent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0, got %d", len(got))
	}
}

func TestSaveReportFilters_IsolatedByReportType(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	if err := d.CreateIDP(ctx, &IdentityProviderRecord{
		ID: "corp-ad", FriendlyName: "Corp AD", ProviderType: "ad",
		Enabled: true, ConfigJSON: "{}",
	}); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	// Save filters for both types.
	if err := d.SaveReportFilters(ctx, "corp-ad", ReportTypeExpiration, []ReportFilter{
		{IDPID: "corp-ad", ReportType: ReportTypeExpiration, Attribute: "dn", Pattern: "expiring-pattern"},
	}); err != nil {
		t.Fatalf("saving expiration filters: %v", err)
	}
	if err := d.SaveReportFilters(ctx, "corp-ad", ReportTypeExpired, []ReportFilter{
		{IDPID: "corp-ad", ReportType: ReportTypeExpired, Attribute: "department", Pattern: "expired-pattern"},
	}); err != nil {
		t.Fatalf("saving expired filters: %v", err)
	}

	// Replacing expiration filters should not touch expired filters.
	if err := d.SaveReportFilters(ctx, "corp-ad", ReportTypeExpiration, nil); err != nil {
		t.Fatalf("clearing expiration filters: %v", err)
	}

	expiring, err := d.ListReportFilters(ctx, "corp-ad", ReportTypeExpiration)
	if err != nil {
		t.Fatalf("listing expiration filters: %v", err)
	}
	if len(expiring) != 0 {
		t.Errorf("expected 0 expiration filters, got %d", len(expiring))
	}

	expired, err := d.ListReportFilters(ctx, "corp-ad", ReportTypeExpired)
	if err != nil {
		t.Fatalf("listing expired filters: %v", err)
	}
	if len(expired) != 1 {
		t.Errorf("expected 1 expired filter, got %d", len(expired))
	}
}

func TestGetReportConfig_ParseUpdatedAtError(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	if err := d.CreateIDP(ctx, &IdentityProviderRecord{
		ID: "corp-ad", FriendlyName: "Corp AD", ProviderType: "ad",
		Enabled: true, ConfigJSON: "{}",
	}); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	_, err := d.Writer().ExecContext(ctx, `
		INSERT INTO report_config (idp_id, report_type, enabled, cron_schedule, days_before_expiration, recipients, exclude_disabled, updated_at)
		VALUES (?, ?, 1, '* * * * *', 7, '', 0, ?)`,
		"corp-ad", ReportTypeExpiration, "not-a-timestamp")
	if err != nil {
		t.Fatalf("inserting malformed report config: %v", err)
	}

	_, err = d.GetReportConfig(ctx, "corp-ad", ReportTypeExpiration)
	if err == nil {
		t.Fatal("expected parse error, got nil")
	}
	if !strings.Contains(err.Error(), "parse report config updated_at") {
		t.Fatalf("expected parse report config updated_at error, got: %v", err)
	}
}

func TestListEnabledReportConfigs_ParseUpdatedAtError(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	if err := d.CreateIDP(ctx, &IdentityProviderRecord{
		ID: "corp-ad", FriendlyName: "Corp AD", ProviderType: "ad",
		Enabled: true, ConfigJSON: "{}",
	}); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	_, err := d.Writer().ExecContext(ctx, `
		INSERT INTO report_config (idp_id, report_type, enabled, cron_schedule, days_before_expiration, recipients, exclude_disabled, updated_at)
		VALUES (?, ?, 1, '* * * * *', 7, '', 0, ?)`,
		"corp-ad", ReportTypeExpired, "bad-ts")
	if err != nil {
		t.Fatalf("inserting malformed report config: %v", err)
	}

	_, err = d.ListEnabledReportConfigs(ctx)
	if err == nil {
		t.Fatal("expected parse error, got nil")
	}
	if !strings.Contains(err.Error(), "parse report config updated_at") {
		t.Fatalf("expected parse report config updated_at error, got: %v", err)
	}
}

func TestListReportFilters_QueryError(t *testing.T) {
	d := newTestDB(t)

	if err := d.Reader().Close(); err != nil {
		t.Fatalf("closing reader: %v", err)
	}

	_, err := d.ListReportFilters(context.Background(), "corp-ad", ReportTypeExpiration)
	if err == nil {
		t.Fatal("expected query error, got nil")
	}
	if !strings.Contains(err.Error(), "list report filters") {
		t.Fatalf("expected list report filters error, got: %v", err)
	}
}

func TestSaveReportFilters_BeginTxError(t *testing.T) {
	d := newTestDB(t)

	if err := d.Writer().Close(); err != nil {
		t.Fatalf("closing writer: %v", err)
	}

	err := d.SaveReportFilters(context.Background(), "corp-ad", ReportTypeExpiration, []ReportFilter{{
		Attribute: "department",
		Pattern:   "IT",
	}})
	if err == nil {
		t.Fatal("expected begin tx error, got nil")
	}
	if !strings.Contains(err.Error(), "beginning transaction") {
		t.Fatalf("expected beginning transaction error, got: %v", err)
	}
}
