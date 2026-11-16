package db

import (
	"context"
	"errors"
	"testing"
)

func TestEmailImageStore_CRUD(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	img := &EmailImage{Name: "Logo", Filename: "abc.png", ContentType: "image/png", SizeBytes: 10, Width: 2, Height: 3}
	if err := d.CreateEmailImage(ctx, img); err != nil {
		t.Fatalf("create: %v", err)
	}
	if img.ID == 0 || img.CreatedAt.IsZero() {
		t.Fatalf("expected ID and CreatedAt to be set: %+v", img)
	}

	got, err := d.GetEmailImage(ctx, img.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Name != "Logo" || got.Filename != "abc.png" || got.Width != 2 || got.Height != 3 {
		t.Errorf("unexpected image: %+v", got)
	}

	if err := d.CreateEmailImage(ctx, &EmailImage{Name: "dup", Filename: "abc.png", ContentType: "image/png"}); err == nil {
		t.Error("expected duplicate filename to be rejected")
	}

	if err := d.UpsertEmailImageByFilename(ctx, &EmailImage{Name: "Renamed", Filename: "abc.png", ContentType: "image/png"}); err != nil {
		t.Fatalf("upsert existing: %v", err)
	}
	if err := d.UpsertEmailImageByFilename(ctx, &EmailImage{Name: "New", Filename: "def.gif", ContentType: "image/gif"}); err != nil {
		t.Fatalf("upsert new: %v", err)
	}

	list, err := d.ListEmailImages(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 images, got %d", len(list))
	}
	got, _ = d.GetEmailImage(ctx, img.ID)
	if got.Name != "Renamed" {
		t.Errorf("expected upsert to rename, got %q", got.Name)
	}

	if err := d.DeleteEmailImage(ctx, img.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := d.GetEmailImage(ctx, img.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound after delete, got %v", err)
	}
	if err := d.DeleteEmailImage(ctx, img.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound deleting twice, got %v", err)
	}
}

func TestEmailTemplate_PriorityDefaultsToNormal(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	if err := d.SaveEmailTemplate(ctx, &EmailTemplate{TemplateType: "x", Subject: "s", BodyHTML: "b"}); err != nil {
		t.Fatal(err)
	}
	got, err := d.GetEmailTemplate(ctx, "x")
	if err != nil || got.Priority != "normal" {
		t.Fatalf("expected normal priority, got %q (%v)", got.Priority, err)
	}

	if err := d.SaveEmailTemplate(ctx, &EmailTemplate{TemplateType: "x", Subject: "s", BodyHTML: "b", Priority: "high"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := d.GetEmailTemplate(ctx, "x"); got.Priority != "high" {
		t.Errorf("expected high priority, got %q", got.Priority)
	}

	// Seeded templates pick up the column default.
	if got, err := d.GetEmailTemplate(ctx, "password_changed"); err == nil && got.Priority != "normal" {
		t.Errorf("seeded template priority = %q, want normal", got.Priority)
	}
}
