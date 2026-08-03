package db

import (
	"context"
	"errors"
	"testing"
)

func createTestIDPRecord(t *testing.T, d *DB, id string) {
	t.Helper()
	err := d.CreateIDP(context.Background(), &IdentityProviderRecord{
		ID:           id,
		FriendlyName: id,
		ProviderType: "ad",
		Enabled:      true,
		ConfigJSON:   "{}",
	})
	if err != nil {
		t.Fatalf("creating idp %q: %v", id, err)
	}
}

func TestCreateIDPGroup_AssignsIncreasingDisplayOrder(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	first := &IDPGroup{Name: "Corporate", Description: "HQ", Icon: "bi-building", Collapsible: true}
	if err := d.CreateIDPGroup(ctx, first); err != nil {
		t.Fatalf("creating first group: %v", err)
	}
	if first.ID == 0 {
		t.Fatal("expected CreateIDPGroup to set the new ID")
	}

	second := &IDPGroup{Name: "Partners"}
	if err := d.CreateIDPGroup(ctx, second); err != nil {
		t.Fatalf("creating second group: %v", err)
	}

	groups, err := d.ListIDPGroups(ctx)
	if err != nil {
		t.Fatalf("listing groups: %v", err)
	}
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(groups))
	}
	if groups[0].ID != first.ID || groups[1].ID != second.ID {
		t.Errorf("expected creation order to be preserved, got %d then %d", groups[0].ID, groups[1].ID)
	}
	if groups[1].DisplayOrder <= groups[0].DisplayOrder {
		t.Errorf("expected the second group to sort after the first, got %d then %d",
			groups[0].DisplayOrder, groups[1].DisplayOrder)
	}
}

func TestGetIDPGroup_RoundTripsFields(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	in := &IDPGroup{Name: "Corporate", Description: "HQ directories", Icon: "bi-building", Collapsible: true, StartCollapsed: true}
	if err := d.CreateIDPGroup(ctx, in); err != nil {
		t.Fatalf("creating group: %v", err)
	}

	got, err := d.GetIDPGroup(ctx, in.ID)
	if err != nil {
		t.Fatalf("getting group: %v", err)
	}
	if got.Name != in.Name || got.Description != in.Description || got.Icon != in.Icon {
		t.Errorf("field mismatch: %+v", got)
	}
	if !got.Collapsible {
		t.Error("expected Collapsible to round-trip as true")
	}
	if !got.StartCollapsed {
		t.Error("expected StartCollapsed to round-trip as true")
	}
	if got.CreatedAt.IsZero() || got.UpdatedAt.IsZero() {
		t.Error("expected timestamps to be parsed")
	}
}

func TestGetIDPGroup_NotFound(t *testing.T) {
	d := newTestDB(t)

	if _, err := d.GetIDPGroup(context.Background(), 999); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

// A group users cannot expand must never start hidden, so the store refuses the
// combination rather than trusting the caller to have paired the two flags.
func TestIDPGroup_StartCollapsedRequiresCollapsible(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	g := &IDPGroup{Name: "Corporate", StartCollapsed: true}
	if err := d.CreateIDPGroup(ctx, g); err != nil {
		t.Fatalf("creating group: %v", err)
	}
	got, err := d.GetIDPGroup(ctx, g.ID)
	if err != nil {
		t.Fatalf("getting group: %v", err)
	}
	if got.StartCollapsed {
		t.Error("expected StartCollapsed to be ignored without Collapsible on create")
	}

	update := &IDPGroup{ID: g.ID, Name: "Corporate", StartCollapsed: true}
	if err := d.UpdateIDPGroup(ctx, update); err != nil {
		t.Fatalf("updating group: %v", err)
	}
	got, err = d.GetIDPGroup(ctx, g.ID)
	if err != nil {
		t.Fatalf("getting group: %v", err)
	}
	if got.StartCollapsed {
		t.Error("expected StartCollapsed to be ignored without Collapsible on update")
	}
}

func TestUpdateIDPGroup_PreservesDisplayOrder(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	first := &IDPGroup{Name: "Corporate"}
	if err := d.CreateIDPGroup(ctx, first); err != nil {
		t.Fatalf("creating first group: %v", err)
	}
	second := &IDPGroup{Name: "Partners"}
	if err := d.CreateIDPGroup(ctx, second); err != nil {
		t.Fatalf("creating second group: %v", err)
	}

	before, err := d.GetIDPGroup(ctx, second.ID)
	if err != nil {
		t.Fatalf("getting group: %v", err)
	}

	update := &IDPGroup{ID: second.ID, Name: "External Partners", Description: "Renamed", Icon: "bi-people"}
	if err := d.UpdateIDPGroup(ctx, update); err != nil {
		t.Fatalf("updating group: %v", err)
	}

	after, err := d.GetIDPGroup(ctx, second.ID)
	if err != nil {
		t.Fatalf("getting group: %v", err)
	}
	if after.Name != "External Partners" || after.Description != "Renamed" || after.Icon != "bi-people" {
		t.Errorf("expected edited fields, got %+v", after)
	}
	if after.Collapsible {
		t.Error("expected Collapsible to be cleared")
	}
	if after.StartCollapsed {
		t.Error("expected StartCollapsed to be cleared")
	}
	if after.DisplayOrder != before.DisplayOrder {
		t.Errorf("expected display order %d to be preserved, got %d", before.DisplayOrder, after.DisplayOrder)
	}
}

func TestUpdateIDPGroup_NotFound(t *testing.T) {
	d := newTestDB(t)

	err := d.UpdateIDPGroup(context.Background(), &IDPGroup{ID: 999, Name: "Ghost"})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestDeleteIDPGroup_UngroupsProvidersWithoutDeletingThem(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	group := &IDPGroup{Name: "Corporate"}
	if err := d.CreateIDPGroup(ctx, group); err != nil {
		t.Fatalf("creating group: %v", err)
	}
	createTestIDPRecord(t, d, "corp-ad")

	err := d.SetIDPArrangement(ctx, []int64{group.ID}, []IDPPlacement{
		{IDPID: "corp-ad", GroupID: &group.ID, DisplayOrder: 0},
	})
	if err != nil {
		t.Fatalf("arranging: %v", err)
	}

	if err := d.DeleteIDPGroup(ctx, group.ID); err != nil {
		t.Fatalf("deleting group: %v", err)
	}

	rec, err := d.GetIDP(ctx, "corp-ad")
	if err != nil {
		t.Fatalf("provider should survive group deletion: %v", err)
	}
	if rec.GroupID != nil {
		t.Errorf("expected provider to be ungrouped, got group %d", *rec.GroupID)
	}
}

// TestDeleteIDPGroup_UngroupsWithForeignKeysOff pins the reason DeleteIDPGroup
// clears group_id itself instead of leaning on ON DELETE SET NULL: migrations
// run with foreign key enforcement disabled, so the constraint cannot be
// assumed to be active on every connection. Without this the previous test
// passes even if the explicit UPDATE is deleted.
func TestDeleteIDPGroup_UngroupsWithForeignKeysOff(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	group := &IDPGroup{Name: "Corporate"}
	if err := d.CreateIDPGroup(ctx, group); err != nil {
		t.Fatalf("creating group: %v", err)
	}
	createTestIDPRecord(t, d, "corp-ad")

	err := d.SetIDPArrangement(ctx, []int64{group.ID}, []IDPPlacement{
		{IDPID: "corp-ad", GroupID: &group.ID, DisplayOrder: 0},
	})
	if err != nil {
		t.Fatalf("arranging: %v", err)
	}

	// The writer pool is capped at one connection, so this affects the same
	// connection DeleteIDPGroup will use.
	if _, err := d.writer.ExecContext(ctx, "PRAGMA foreign_keys = OFF"); err != nil {
		t.Fatalf("disabling foreign keys: %v", err)
	}
	t.Cleanup(func() { _, _ = d.writer.ExecContext(ctx, "PRAGMA foreign_keys = ON") })

	if err := d.DeleteIDPGroup(ctx, group.ID); err != nil {
		t.Fatalf("deleting group: %v", err)
	}

	rec, err := d.GetIDP(ctx, "corp-ad")
	if err != nil {
		t.Fatalf("provider should survive group deletion: %v", err)
	}
	if rec.GroupID != nil {
		t.Errorf("expected provider to be ungrouped without the foreign key, got group %d", *rec.GroupID)
	}
}

func TestDeleteIDPGroup_NotFound(t *testing.T) {
	d := newTestDB(t)

	if err := d.DeleteIDPGroup(context.Background(), 999); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestGetLocalAdminPlacement_DefaultsToUngrouped(t *testing.T) {
	d := newTestDB(t)

	p, err := d.GetLocalAdminPlacement(context.Background())
	if err != nil {
		t.Fatalf("getting placement: %v", err)
	}
	if p.GroupID != nil {
		t.Errorf("expected no group by default, got %d", *p.GroupID)
	}
	if p.DisplayOrder != 0 {
		t.Errorf("expected display order 0, got %d", p.DisplayOrder)
	}
}

// Local Admin has no identity_providers row, so SetIDPArrangement has to route
// its placement to a table of its own instead of issuing an UPDATE that would
// silently match nothing.
func TestSetIDPArrangement_PlacesLocalAdmin(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	group := &IDPGroup{Name: "Corporate"}
	if err := d.CreateIDPGroup(ctx, group); err != nil {
		t.Fatalf("creating group: %v", err)
	}
	createTestIDPRecord(t, d, "corp-ad")

	err := d.SetIDPArrangement(ctx, []int64{group.ID}, []IDPPlacement{
		{IDPID: "corp-ad", GroupID: &group.ID, DisplayOrder: 0},
		{IDPID: LocalAdminIDPID, GroupID: &group.ID, DisplayOrder: 1},
	})
	if err != nil {
		t.Fatalf("arranging: %v", err)
	}

	p, err := d.GetLocalAdminPlacement(ctx)
	if err != nil {
		t.Fatalf("getting placement: %v", err)
	}
	if p.GroupID == nil || *p.GroupID != group.ID {
		t.Fatalf("expected local admin in group %d, got %v", group.ID, p.GroupID)
	}
	if p.DisplayOrder != 1 {
		t.Errorf("expected display order 1, got %d", p.DisplayOrder)
	}

	// Re-arranging must overwrite the singleton row, not add another.
	err = d.SetIDPArrangement(ctx, []int64{group.ID}, []IDPPlacement{
		{IDPID: LocalAdminIDPID, DisplayOrder: 3},
	})
	if err != nil {
		t.Fatalf("re-arranging: %v", err)
	}
	p, err = d.GetLocalAdminPlacement(ctx)
	if err != nil {
		t.Fatalf("getting placement: %v", err)
	}
	if p.GroupID != nil {
		t.Errorf("expected local admin ungrouped, got group %d", *p.GroupID)
	}
	if p.DisplayOrder != 3 {
		t.Errorf("expected display order 3, got %d", p.DisplayOrder)
	}
}

// Deleting a group must release Local Admin too, and without relying on the
// foreign key, for the same reason as the provider case above.
func TestDeleteIDPGroup_UngroupsLocalAdminWithForeignKeysOff(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	group := &IDPGroup{Name: "Corporate"}
	if err := d.CreateIDPGroup(ctx, group); err != nil {
		t.Fatalf("creating group: %v", err)
	}
	err := d.SetIDPArrangement(ctx, []int64{group.ID}, []IDPPlacement{
		{IDPID: LocalAdminIDPID, GroupID: &group.ID, DisplayOrder: 0},
	})
	if err != nil {
		t.Fatalf("arranging: %v", err)
	}

	if _, err := d.writer.ExecContext(ctx, "PRAGMA foreign_keys = OFF"); err != nil {
		t.Fatalf("disabling foreign keys: %v", err)
	}
	t.Cleanup(func() { _, _ = d.writer.ExecContext(ctx, "PRAGMA foreign_keys = ON") })

	if err := d.DeleteIDPGroup(ctx, group.ID); err != nil {
		t.Fatalf("deleting group: %v", err)
	}

	p, err := d.GetLocalAdminPlacement(ctx)
	if err != nil {
		t.Fatalf("getting placement: %v", err)
	}
	if p.GroupID != nil {
		t.Errorf("expected local admin ungrouped, got group %d", *p.GroupID)
	}
}

func TestSetIDPArrangement_OrdersGroupsAndProviders(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	corp := &IDPGroup{Name: "Corporate"}
	if err := d.CreateIDPGroup(ctx, corp); err != nil {
		t.Fatalf("creating group: %v", err)
	}
	partners := &IDPGroup{Name: "Partners"}
	if err := d.CreateIDPGroup(ctx, partners); err != nil {
		t.Fatalf("creating group: %v", err)
	}

	// Names are deliberately reverse-alphabetical to the intended order, so a
	// pass only proves display_order is being honoured.
	createTestIDPRecord(t, d, "zeta")
	createTestIDPRecord(t, d, "alpha")
	createTestIDPRecord(t, d, "loose")

	err := d.SetIDPArrangement(ctx, []int64{partners.ID, corp.ID}, []IDPPlacement{
		{IDPID: "zeta", GroupID: &corp.ID, DisplayOrder: 0},
		{IDPID: "alpha", GroupID: &corp.ID, DisplayOrder: 1},
		{IDPID: "loose", GroupID: nil, DisplayOrder: 2},
	})
	if err != nil {
		t.Fatalf("arranging: %v", err)
	}

	groups, err := d.ListIDPGroups(ctx)
	if err != nil {
		t.Fatalf("listing groups: %v", err)
	}
	if groups[0].ID != partners.ID || groups[1].ID != corp.ID {
		t.Errorf("expected Partners before Corporate, got %d then %d", groups[0].ID, groups[1].ID)
	}

	idps, err := d.ListIDPs(ctx)
	if err != nil {
		t.Fatalf("listing idps: %v", err)
	}
	var order []string
	for _, rec := range idps {
		order = append(order, rec.ID)
	}
	want := []string{"zeta", "alpha", "loose"}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("expected provider order %v, got %v", want, order)
		}
	}

	loose, err := d.GetIDP(ctx, "loose")
	if err != nil {
		t.Fatalf("getting provider: %v", err)
	}
	if loose.GroupID != nil {
		t.Errorf("expected a nil GroupID to leave the provider ungrouped, got %d", *loose.GroupID)
	}
	grouped, err := d.GetIDP(ctx, "zeta")
	if err != nil {
		t.Fatalf("getting provider: %v", err)
	}
	if grouped.GroupID == nil || *grouped.GroupID != corp.ID {
		t.Errorf("expected provider to be in group %d, got %v", corp.ID, grouped.GroupID)
	}
}

func TestSetIDPArrangement_RollsBackOnFailure(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	corp := &IDPGroup{Name: "Corporate"}
	if err := d.CreateIDPGroup(ctx, corp); err != nil {
		t.Fatalf("creating group: %v", err)
	}
	createTestIDPRecord(t, d, "corp-ad")

	missing := corp.ID + 500
	err := d.SetIDPArrangement(ctx, []int64{corp.ID}, []IDPPlacement{
		{IDPID: "corp-ad", GroupID: &corp.ID, DisplayOrder: 0},
		{IDPID: "corp-ad", GroupID: &missing, DisplayOrder: 1},
	})
	if err == nil {
		t.Fatal("expected placement into a nonexistent group to fail")
	}

	rec, getErr := d.GetIDP(ctx, "corp-ad")
	if getErr != nil {
		t.Fatalf("getting provider: %v", getErr)
	}
	if rec.GroupID != nil {
		t.Errorf("expected the earlier placement to be rolled back, got group %d", *rec.GroupID)
	}
}

func TestUpdateIDP_PreservesGrouping(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	corp := &IDPGroup{Name: "Corporate"}
	if err := d.CreateIDPGroup(ctx, corp); err != nil {
		t.Fatalf("creating group: %v", err)
	}
	createTestIDPRecord(t, d, "corp-ad")
	err := d.SetIDPArrangement(ctx, []int64{corp.ID}, []IDPPlacement{
		{IDPID: "corp-ad", GroupID: &corp.ID, DisplayOrder: 3},
	})
	if err != nil {
		t.Fatalf("arranging: %v", err)
	}

	rec, err := d.GetIDP(ctx, "corp-ad")
	if err != nil {
		t.Fatalf("getting provider: %v", err)
	}
	rec.FriendlyName = "Renamed"
	if err := d.UpdateIDP(ctx, rec); err != nil {
		t.Fatalf("updating provider: %v", err)
	}

	after, err := d.GetIDP(ctx, "corp-ad")
	if err != nil {
		t.Fatalf("getting provider: %v", err)
	}
	if after.GroupID == nil || *after.GroupID != corp.ID {
		t.Errorf("editing a provider must not clear its group, got %v", after.GroupID)
	}
	if after.DisplayOrder != 3 {
		t.Errorf("editing a provider must not reset its position, got %d", after.DisplayOrder)
	}
}
