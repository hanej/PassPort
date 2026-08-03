package migrate

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/hanej/passport/internal/db"
)

// openSeparateDB opens a file-backed database. openTestDB cannot be used for
// both sides of an import test: OpenMemory uses SQLite's shared cache, so every
// in-memory handle in the process refers to one and the same database.
func openSeparateDB(t *testing.T, name string) *db.DB {
	t.Helper()
	database, err := db.Open(filepath.Join(t.TempDir(), name+".db"))
	if err != nil {
		t.Fatalf("opening db: %v", err)
	}
	if err := database.Migrate(context.Background()); err != nil {
		t.Fatalf("running migrations: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return database
}

// seedArrangement creates two groups, places the given providers, and returns
// the group IDs in display order.
func seedArrangement(t *testing.T, store db.Store) (corpID, partnersID int64) {
	t.Helper()
	ctx := context.Background()

	corp := &db.IDPGroup{Name: "Corporate", Description: "HQ", Icon: "bi-building", Collapsible: true, StartCollapsed: true}
	if err := store.CreateIDPGroup(ctx, corp); err != nil {
		t.Fatalf("creating group: %v", err)
	}
	partners := &db.IDPGroup{Name: "Partners"}
	if err := store.CreateIDPGroup(ctx, partners); err != nil {
		t.Fatalf("creating group: %v", err)
	}
	return corp.ID, partners.ID
}

func TestExportImport_RoundTripsProviderGroups(t *testing.T) {
	ctx := context.Background()
	src := openSeparateDB(t, "src")
	cryptoSvc := newCrypto(t)

	seedIDP(t, src, cryptoSvc, "corp-ad", "Corporate AD")
	seedIDP(t, src, cryptoSvc, "partner-ipa", "Partner IPA")
	seedIDP(t, src, cryptoSvc, "loose", "Unassigned")
	corpID, partnersID := seedArrangement(t, src)

	// Partners is deliberately ordered before Corporate to prove group order is
	// carried, not re-derived from creation order.
	err := src.SetIDPArrangement(ctx, []int64{partnersID, corpID}, []db.IDPPlacement{
		{IDPID: "partner-ipa", GroupID: &partnersID, DisplayOrder: 0},
		{IDPID: "corp-ad", GroupID: &corpID, DisplayOrder: 1},
		{IDPID: "loose", GroupID: nil, DisplayOrder: 2},
	})
	if err != nil {
		t.Fatalf("arranging: %v", err)
	}

	data, err := BuildExport(ctx, src, cryptoSvc)
	if err != nil {
		t.Fatalf("building export: %v", err)
	}
	if len(data.IDPGroups) != 2 {
		t.Fatalf("expected 2 exported groups, got %d", len(data.IDPGroups))
	}
	if data.IDPGroups[0].DisplayOrder != 0 || data.IDPGroups[1].DisplayOrder != 1 {
		t.Errorf("expected exported display orders 0 and 1, got %d and %d",
			data.IDPGroups[0].DisplayOrder, data.IDPGroups[1].DisplayOrder)
	}

	dst := openSeparateDB(t, "dst")
	result, err := RunImport(ctx, dst, cryptoSvc, data, AllSections())
	if err != nil {
		t.Fatalf("running import: %v", err)
	}
	if result.IDPGroups != 2 {
		t.Errorf("expected 2 imported groups, got %d", result.IDPGroups)
	}
	if len(result.Errors) != 0 {
		t.Fatalf("unexpected import errors: %v", result.Errors)
	}

	groups, err := dst.ListIDPGroups(ctx)
	if err != nil {
		t.Fatalf("listing groups: %v", err)
	}
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(groups))
	}
	if groups[0].Name != "Partners" || groups[1].Name != "Corporate" {
		t.Errorf("expected Partners then Corporate, got %q then %q", groups[0].Name, groups[1].Name)
	}
	if groups[1].Icon != "bi-building" || !groups[1].Collapsible || groups[1].Description != "HQ" {
		t.Errorf("group fields did not round-trip: %+v", groups[1])
	}
	if !groups[1].StartCollapsed {
		t.Errorf("expected StartCollapsed to round-trip: %+v", groups[1])
	}

	idps, err := dst.ListIDPs(ctx)
	if err != nil {
		t.Fatalf("listing idps: %v", err)
	}
	want := []string{"partner-ipa", "corp-ad", "loose"}
	for i, id := range want {
		if idps[i].ID != id {
			t.Fatalf("expected provider order %v, got %s at index %d", want, idps[i].ID, i)
		}
	}

	corp, err := dst.GetIDP(ctx, "corp-ad")
	if err != nil {
		t.Fatalf("getting provider: %v", err)
	}
	if corp.GroupID == nil || *corp.GroupID != groups[1].ID {
		t.Errorf("expected corp-ad in the Corporate group, got %v", corp.GroupID)
	}
	loose, err := dst.GetIDP(ctx, "loose")
	if err != nil {
		t.Fatalf("getting provider: %v", err)
	}
	if loose.GroupID != nil {
		t.Errorf("expected loose to stay ungrouped, got group %d", *loose.GroupID)
	}
}

// Local Admin is not an identity_providers row, so its group assignment would
// be dropped by an export that only walks the provider table.
func TestExportImport_RoundTripsLocalAdminPlacement(t *testing.T) {
	ctx := context.Background()
	src := openSeparateDB(t, "src")
	cryptoSvc := newCrypto(t)

	seedIDP(t, src, cryptoSvc, "corp-ad", "Corporate AD")
	corpID, _ := seedArrangement(t, src)

	err := src.SetIDPArrangement(ctx, []int64{corpID}, []db.IDPPlacement{
		{IDPID: "corp-ad", GroupID: &corpID, DisplayOrder: 0},
		{IDPID: db.LocalAdminIDPID, GroupID: &corpID, DisplayOrder: 1},
	})
	if err != nil {
		t.Fatalf("arranging: %v", err)
	}

	data, err := BuildExport(ctx, src, cryptoSvc)
	if err != nil {
		t.Fatalf("building export: %v", err)
	}
	if data.LocalAdminPlacement == nil {
		t.Fatal("expected local admin placement in the export")
	}
	if data.LocalAdminPlacement.GroupName != "Corporate" {
		t.Errorf("expected group name Corporate, got %q", data.LocalAdminPlacement.GroupName)
	}
	if data.LocalAdminPlacement.DisplayOrder != 1 {
		t.Errorf("expected display order 1, got %d", data.LocalAdminPlacement.DisplayOrder)
	}

	dst := openSeparateDB(t, "dst")
	result, err := RunImport(ctx, dst, cryptoSvc, data, AllSections())
	if err != nil {
		t.Fatalf("running import: %v", err)
	}
	if len(result.Errors) != 0 {
		t.Fatalf("unexpected import errors: %v", result.Errors)
	}

	groups, err := dst.ListIDPGroups(ctx)
	if err != nil {
		t.Fatalf("listing groups: %v", err)
	}
	var wantID int64 = -1
	for _, g := range groups {
		if g.Name == "Corporate" {
			wantID = g.ID
		}
	}
	if wantID == -1 {
		t.Fatal("Corporate group missing after import")
	}

	p, err := dst.GetLocalAdminPlacement(ctx)
	if err != nil {
		t.Fatalf("getting placement: %v", err)
	}
	if p.GroupID == nil || *p.GroupID != wantID {
		t.Fatalf("expected local admin in Corporate (id %d), got %v", wantID, p.GroupID)
	}
	if p.DisplayOrder != 1 {
		t.Errorf("expected display order 1, got %d", p.DisplayOrder)
	}
}

// TestImport_MatchesExistingGroupsByName covers importing into an installation
// that already has a group of the same name: it must be reused, not duplicated.
func TestImport_MatchesExistingGroupsByName(t *testing.T) {
	ctx := context.Background()
	src := openSeparateDB(t, "src")
	cryptoSvc := newCrypto(t)

	seedIDP(t, src, cryptoSvc, "corp-ad", "Corporate AD")
	corpID, _ := seedArrangement(t, src)
	err := src.SetIDPArrangement(ctx, []int64{corpID}, []db.IDPPlacement{
		{IDPID: "corp-ad", GroupID: &corpID, DisplayOrder: 0},
	})
	if err != nil {
		t.Fatalf("arranging: %v", err)
	}

	data, err := BuildExport(ctx, src, cryptoSvc)
	if err != nil {
		t.Fatalf("building export: %v", err)
	}

	dst := openSeparateDB(t, "dst")
	if err := dst.CreateIDPGroup(ctx, &db.IDPGroup{Name: "Corporate", Description: "stale"}); err != nil {
		t.Fatalf("creating existing group: %v", err)
	}

	if _, err := RunImport(ctx, dst, cryptoSvc, data, AllSections()); err != nil {
		t.Fatalf("running import: %v", err)
	}

	groups, err := dst.ListIDPGroups(ctx)
	if err != nil {
		t.Fatalf("listing groups: %v", err)
	}
	var corporate int
	for _, g := range groups {
		if g.Name == "Corporate" {
			corporate++
			if g.Description != "HQ" {
				t.Errorf("expected the existing group to be updated, got description %q", g.Description)
			}
		}
	}
	if corporate != 1 {
		t.Errorf("expected exactly one Corporate group, got %d", corporate)
	}
}

// TestImport_LegacyFileKeepsLocalArrangement covers export files written before
// provider groups existed. They carry no groups and no display order, so
// applying an arrangement would flatten whatever the admin has set up locally.
func TestImport_LegacyFileKeepsLocalArrangement(t *testing.T) {
	ctx := context.Background()
	dst := openSeparateDB(t, "dst")
	cryptoSvc := newCrypto(t)

	seedIDP(t, dst, cryptoSvc, "corp-ad", "Corporate AD")
	corpID, _ := seedArrangement(t, dst)
	err := dst.SetIDPArrangement(ctx, []int64{corpID}, []db.IDPPlacement{
		{IDPID: "corp-ad", GroupID: &corpID, DisplayOrder: 7},
	})
	if err != nil {
		t.Fatalf("arranging: %v", err)
	}

	legacy := &ExportData{
		Version: 1,
		IdentityProviders: []ExportIDP{{
			ID:           "corp-ad",
			FriendlyName: "Corporate AD",
			ProviderType: "ad",
			Enabled:      true,
			Config:       []byte(`{}`),
			Secrets:      []byte(`{}`),
		}},
	}

	if _, err := RunImport(ctx, dst, cryptoSvc, legacy, AllSections()); err != nil {
		t.Fatalf("running import: %v", err)
	}

	rec, err := dst.GetIDP(ctx, "corp-ad")
	if err != nil {
		t.Fatalf("getting provider: %v", err)
	}
	if rec.GroupID == nil || *rec.GroupID != corpID {
		t.Errorf("legacy import must not ungroup a provider, got %v", rec.GroupID)
	}
	if rec.DisplayOrder != 7 {
		t.Errorf("legacy import must not reset display order, got %d", rec.DisplayOrder)
	}
}

// TestImport_MatchesGroupNamesCaseInsensitively mirrors the admin UI, which
// treats names differing only in case as the same group.
func TestImport_MatchesGroupNamesCaseInsensitively(t *testing.T) {
	ctx := context.Background()
	dst := openSeparateDB(t, "dst")
	cryptoSvc := newCrypto(t)

	if err := dst.CreateIDPGroup(ctx, &db.IDPGroup{Name: "corporate"}); err != nil {
		t.Fatalf("creating existing group: %v", err)
	}

	data := &ExportData{
		Version:   1,
		IDPGroups: []ExportIDPGroup{{Name: "Corporate", Description: "HQ"}},
		IdentityProviders: []ExportIDP{{
			ID:           "corp-ad",
			FriendlyName: "Corporate AD",
			ProviderType: "ad",
			Enabled:      true,
			GroupName:    "Corporate",
			Config:       []byte(`{}`),
			Secrets:      []byte(`{}`),
		}},
	}

	if _, err := RunImport(ctx, dst, cryptoSvc, data, AllSections()); err != nil {
		t.Fatalf("running import: %v", err)
	}

	groups, err := dst.ListIDPGroups(ctx)
	if err != nil {
		t.Fatalf("listing groups: %v", err)
	}
	if len(groups) != 1 {
		t.Fatalf("expected the existing group to be reused, got %d groups", len(groups))
	}
	rec, err := dst.GetIDP(ctx, "corp-ad")
	if err != nil {
		t.Fatalf("getting provider: %v", err)
	}
	if rec.GroupID == nil || *rec.GroupID != groups[0].ID {
		t.Errorf("expected the provider to land in the existing group, got %v", rec.GroupID)
	}
}

// TestImport_RestoresOrderingWithoutGroups covers an admin who ordered
// providers but never created a group: the ordering still has to survive.
func TestImport_RestoresOrderingWithoutGroups(t *testing.T) {
	ctx := context.Background()
	src := openSeparateDB(t, "src")
	cryptoSvc := newCrypto(t)

	seedIDP(t, src, cryptoSvc, "aaa", "Alpha")
	seedIDP(t, src, cryptoSvc, "zzz", "Zulu")
	err := src.SetIDPArrangement(ctx, nil, []db.IDPPlacement{
		{IDPID: "zzz", DisplayOrder: 0},
		{IDPID: "aaa", DisplayOrder: 1},
	})
	if err != nil {
		t.Fatalf("arranging: %v", err)
	}

	data, err := BuildExport(ctx, src, cryptoSvc)
	if err != nil {
		t.Fatalf("building export: %v", err)
	}
	if len(data.IDPGroups) != 0 {
		t.Fatalf("expected no exported groups, got %d", len(data.IDPGroups))
	}

	dst := openSeparateDB(t, "dst")
	if _, err := RunImport(ctx, dst, cryptoSvc, data, AllSections()); err != nil {
		t.Fatalf("running import: %v", err)
	}

	idps, err := dst.ListIDPs(ctx)
	if err != nil {
		t.Fatalf("listing idps: %v", err)
	}
	if len(idps) != 2 || idps[0].ID != "zzz" || idps[1].ID != "aaa" {
		t.Errorf("expected zzz before aaa, got %+v", idps)
	}
}

// TestImport_SortsGroupsByDisplayOrderNotFileOrder covers the one case where
// the exported display_order matters: a hand-edited or reordered file whose
// idp_groups array is not already in display order.
func TestImport_SortsGroupsByDisplayOrderNotFileOrder(t *testing.T) {
	ctx := context.Background()
	src := openSeparateDB(t, "src")
	cryptoSvc := newCrypto(t)

	seedIDP(t, src, cryptoSvc, "corp-ad", "Corporate AD")
	seedIDP(t, src, cryptoSvc, "partner-ipa", "Partner IPA")
	corpID, partnersID := seedArrangement(t, src)

	err := src.SetIDPArrangement(ctx, []int64{corpID, partnersID}, []db.IDPPlacement{
		{IDPID: "corp-ad", GroupID: &corpID, DisplayOrder: 0},
		{IDPID: "partner-ipa", GroupID: &partnersID, DisplayOrder: 1},
	})
	if err != nil {
		t.Fatalf("arranging: %v", err)
	}

	data, err := BuildExport(ctx, src, cryptoSvc)
	if err != nil {
		t.Fatalf("building export: %v", err)
	}

	// Shuffle the array while leaving display_order alone, as an edited file
	// would. Import must follow display_order, not the array position.
	if data.IDPGroups[0].Name != "Corporate" {
		t.Fatalf("expected Corporate first in the export, got %q", data.IDPGroups[0].Name)
	}
	data.IDPGroups[0], data.IDPGroups[1] = data.IDPGroups[1], data.IDPGroups[0]

	dst := openSeparateDB(t, "dst")
	if _, err := RunImport(ctx, dst, cryptoSvc, data, AllSections()); err != nil {
		t.Fatalf("running import: %v", err)
	}

	groups, err := dst.ListIDPGroups(ctx)
	if err != nil {
		t.Fatalf("listing groups: %v", err)
	}
	if len(groups) != 2 || groups[0].Name != "Corporate" || groups[1].Name != "Partners" {
		t.Fatalf("expected Corporate then Partners from display_order, got %+v", groups)
	}
}
