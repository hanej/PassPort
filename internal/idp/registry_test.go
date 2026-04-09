package idp

import (
	"context"
	"log/slog"
	"testing"
)

// mockProvider implements Provider for registry testing.
type mockProvider struct {
	id           string
	providerType ProviderType
}

func (m *mockProvider) Authenticate(_ context.Context, _, _ string) error           { return nil }
func (m *mockProvider) ChangePassword(_ context.Context, _, _, _ string) error      { return nil }
func (m *mockProvider) ResetPassword(_ context.Context, _, _ string) error          { return nil }
func (m *mockProvider) UnlockAccount(_ context.Context, _ string) error             { return nil }
func (m *mockProvider) EnableAccount(_ context.Context, _ string) error             { return nil }
func (m *mockProvider) GetUserGroups(_ context.Context, _ string) ([]string, error) { return nil, nil }
func (m *mockProvider) GetGroupMembers(_ context.Context, _ string) ([]string, error) {
	return nil, nil
}
func (m *mockProvider) TestConnection(_ context.Context) error                    { return nil }
func (m *mockProvider) SearchUser(_ context.Context, _, _ string) (string, error) { return "", nil }
func (m *mockProvider) GetUserAttribute(_ context.Context, _, _ string) (string, error) {
	return "", nil
}
func (m *mockProvider) Type() ProviderType { return m.providerType }
func (m *mockProvider) ID() string         { return m.id }

func TestRegistry_RegisterAndGet(t *testing.T) {
	r := NewRegistry(slog.Default())
	p := &mockProvider{id: "idp-1", providerType: ProviderTypeAD}

	r.Register("idp-1", p)

	got, ok := r.Get("idp-1")
	if !ok {
		t.Fatal("expected provider to be found")
	}
	if got.ID() != "idp-1" {
		t.Errorf("expected id %q, got %q", "idp-1", got.ID())
	}
}

func TestRegistry_Unregister(t *testing.T) {
	r := NewRegistry(slog.Default())
	p := &mockProvider{id: "idp-1", providerType: ProviderTypeAD}

	r.Register("idp-1", p)
	r.Unregister("idp-1")

	_, ok := r.Get("idp-1")
	if ok {
		t.Fatal("expected provider to be removed after unregister")
	}
}

func TestRegistry_GetUnknown(t *testing.T) {
	r := NewRegistry(slog.Default())

	_, ok := r.Get("nonexistent")
	if ok {
		t.Fatal("expected false for unknown provider")
	}
}

func TestRegistry_GetUnknown_WithRegisteredProviders(t *testing.T) {
	// This test exercises the for-range loop inside the !ok branch, which is only
	// reached when the registry is non-empty but the requested ID is not found.
	r := NewRegistry(slog.Default())
	r.Register("idp-1", &mockProvider{id: "idp-1", providerType: ProviderTypeAD})

	_, ok := r.Get("nonexistent")
	if ok {
		t.Fatal("expected false for unknown provider")
	}
}

func TestRegistry_List(t *testing.T) {
	r := NewRegistry(slog.Default())

	r.Register("idp-1", &mockProvider{id: "idp-1", providerType: ProviderTypeAD})
	r.Register("idp-2", &mockProvider{id: "idp-2", providerType: ProviderTypeFreeIPA})

	list := r.List()
	if len(list) != 2 {
		t.Fatalf("expected 2 providers, got %d", len(list))
	}

	ids := map[string]bool{}
	for _, p := range list {
		ids[p.ID()] = true
	}
	if !ids["idp-1"] || !ids["idp-2"] {
		t.Errorf("expected both idp-1 and idp-2 in list, got %v", ids)
	}
}

func TestRegistry_RegisterOverwrite(t *testing.T) {
	r := NewRegistry(slog.Default())

	r.Register("idp-1", &mockProvider{id: "idp-1", providerType: ProviderTypeAD})
	r.Register("idp-1", &mockProvider{id: "idp-1", providerType: ProviderTypeFreeIPA})

	got, ok := r.Get("idp-1")
	if !ok {
		t.Fatal("expected provider to be found")
	}
	if got.Type() != ProviderTypeFreeIPA {
		t.Errorf("expected overwritten type %q, got %q", ProviderTypeFreeIPA, got.Type())
	}

	list := r.List()
	if len(list) != 1 {
		t.Errorf("expected 1 provider after overwrite, got %d", len(list))
	}
}

func TestRegistry_UnregisterNonexistent(t *testing.T) {
	r := NewRegistry(slog.Default())
	// Should not panic.
	r.Unregister("nonexistent")
}
