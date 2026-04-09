package db

import (
	"context"
	"testing"
)

func TestSetCorrelationWarning_InsertAndList(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	w := &CorrelationWarning{
		AuthUsername: "jdoe",
		TargetIDPID:  "idp-1",
		WarningType:  "ambiguous_match",
		Message:      "multiple accounts found",
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
	if warnings[0].AuthUsername != "jdoe" {
		t.Errorf("expected jdoe, got %s", warnings[0].AuthUsername)
	}
	if warnings[0].TargetIDPID != "idp-1" {
		t.Errorf("expected idp-1, got %s", warnings[0].TargetIDPID)
	}
	if warnings[0].WarningType != "ambiguous_match" {
		t.Errorf("expected ambiguous_match, got %s", warnings[0].WarningType)
	}
	if warnings[0].Message != "multiple accounts found" {
		t.Errorf("unexpected message: %s", warnings[0].Message)
	}
	if warnings[0].ID == 0 {
		t.Error("expected non-zero ID")
	}
	if warnings[0].CreatedAt.IsZero() {
		t.Error("expected non-zero CreatedAt")
	}
}

func TestSetCorrelationWarning_Upsert(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	// Insert once.
	w1 := &CorrelationWarning{
		AuthUsername: "jdoe",
		TargetIDPID:  "idp-1",
		WarningType:  "ambiguous_match",
		Message:      "first",
	}
	if err := d.SetCorrelationWarning(ctx, w1); err != nil {
		t.Fatalf("first SetCorrelationWarning: %v", err)
	}

	// Insert again with same (auth_username, target_idp_id) — should replace.
	w2 := &CorrelationWarning{
		AuthUsername: "jdoe",
		TargetIDPID:  "idp-1",
		WarningType:  "no_match",
		Message:      "updated",
	}
	if err := d.SetCorrelationWarning(ctx, w2); err != nil {
		t.Fatalf("second SetCorrelationWarning: %v", err)
	}

	warnings, err := d.ListCorrelationWarnings(ctx, "jdoe")
	if err != nil {
		t.Fatalf("ListCorrelationWarnings: %v", err)
	}
	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning after upsert, got %d", len(warnings))
	}
	if warnings[0].WarningType != "no_match" {
		t.Errorf("expected no_match after upsert, got %s", warnings[0].WarningType)
	}
	if warnings[0].Message != "updated" {
		t.Errorf("expected 'updated', got %s", warnings[0].Message)
	}
}

func TestSetCorrelationWarning_MultipleIDPs(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	for _, idp := range []string{"idp-1", "idp-2", "idp-3"} {
		w := &CorrelationWarning{
			AuthUsername: "jdoe",
			TargetIDPID:  idp,
			WarningType:  "ambiguous_match",
			Message:      "warning for " + idp,
		}
		if err := d.SetCorrelationWarning(ctx, w); err != nil {
			t.Fatalf("SetCorrelationWarning for %s: %v", idp, err)
		}
	}

	warnings, err := d.ListCorrelationWarnings(ctx, "jdoe")
	if err != nil {
		t.Fatalf("ListCorrelationWarnings: %v", err)
	}
	if len(warnings) != 3 {
		t.Errorf("expected 3 warnings, got %d", len(warnings))
	}
}

func TestListCorrelationWarnings_EmptyForUser(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	warnings, err := d.ListCorrelationWarnings(ctx, "nobody")
	if err != nil {
		t.Fatalf("ListCorrelationWarnings: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("expected 0 warnings, got %d", len(warnings))
	}
}

func TestListCorrelationWarnings_IsolatedByUser(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	// Warning for jdoe.
	if err := d.SetCorrelationWarning(ctx, &CorrelationWarning{
		AuthUsername: "jdoe", TargetIDPID: "idp-x", WarningType: "t", Message: "m",
	}); err != nil {
		t.Fatalf("SetCorrelationWarning: %v", err)
	}
	// Warning for another user.
	if err := d.SetCorrelationWarning(ctx, &CorrelationWarning{
		AuthUsername: "alice", TargetIDPID: "idp-x", WarningType: "t", Message: "m",
	}); err != nil {
		t.Fatalf("SetCorrelationWarning: %v", err)
	}

	warnings, err := d.ListCorrelationWarnings(ctx, "jdoe")
	if err != nil {
		t.Fatalf("ListCorrelationWarnings: %v", err)
	}
	if len(warnings) != 1 {
		t.Errorf("expected 1 warning for jdoe, got %d", len(warnings))
	}
}

func TestDeleteCorrelationWarning_Exists(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	if err := d.SetCorrelationWarning(ctx, &CorrelationWarning{
		AuthUsername: "jdoe", TargetIDPID: "idp-1", WarningType: "t", Message: "m",
	}); err != nil {
		t.Fatalf("SetCorrelationWarning: %v", err)
	}

	if err := d.DeleteCorrelationWarning(ctx, "jdoe", "idp-1"); err != nil {
		t.Fatalf("DeleteCorrelationWarning: %v", err)
	}

	warnings, err := d.ListCorrelationWarnings(ctx, "jdoe")
	if err != nil {
		t.Fatalf("ListCorrelationWarnings after delete: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("expected 0 warnings after delete, got %d", len(warnings))
	}
}

func TestDeleteCorrelationWarning_NonExistent(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	// Deleting a non-existent warning should not error.
	if err := d.DeleteCorrelationWarning(ctx, "nobody", "idp-1"); err != nil {
		t.Errorf("unexpected error deleting non-existent warning: %v", err)
	}
}

func TestDeleteCorrelationWarning_OnlyDeletesMatching(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	// Create two warnings for the same user, different IDPs.
	for _, idp := range []string{"idp-1", "idp-2"} {
		if err := d.SetCorrelationWarning(ctx, &CorrelationWarning{
			AuthUsername: "jdoe", TargetIDPID: idp, WarningType: "t", Message: "m",
		}); err != nil {
			t.Fatalf("SetCorrelationWarning: %v", err)
		}
	}

	// Delete only idp-1.
	if err := d.DeleteCorrelationWarning(ctx, "jdoe", "idp-1"); err != nil {
		t.Fatalf("DeleteCorrelationWarning: %v", err)
	}

	warnings, err := d.ListCorrelationWarnings(ctx, "jdoe")
	if err != nil {
		t.Fatalf("ListCorrelationWarnings: %v", err)
	}
	if len(warnings) != 1 {
		t.Fatalf("expected 1 remaining warning, got %d", len(warnings))
	}
	if warnings[0].TargetIDPID != "idp-2" {
		t.Errorf("expected idp-2 to remain, got %s", warnings[0].TargetIDPID)
	}
}
