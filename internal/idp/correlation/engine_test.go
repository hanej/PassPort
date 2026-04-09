package correlation

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/hanej/passport/internal/db"
	"github.com/hanej/passport/internal/idp"
)

// ---------------------------------------------------------------------------
// Mock provider
// ---------------------------------------------------------------------------

type mockProvider struct {
	id          string
	provType    idp.ProviderType
	searchFunc  func(ctx context.Context, attr, value string) (string, error)
	getAttrFunc func(ctx context.Context, userDN, attr string) (string, error)
}

func (m *mockProvider) Authenticate(context.Context, string, string) error           { return nil }
func (m *mockProvider) ChangePassword(context.Context, string, string, string) error { return nil }
func (m *mockProvider) ResetPassword(context.Context, string, string) error          { return nil }
func (m *mockProvider) UnlockAccount(context.Context, string) error                  { return nil }
func (m *mockProvider) EnableAccount(context.Context, string) error                  { return nil }
func (m *mockProvider) GetUserGroups(context.Context, string) ([]string, error)      { return nil, nil }
func (m *mockProvider) GetGroupMembers(context.Context, string) ([]string, error)    { return nil, nil }
func (m *mockProvider) TestConnection(context.Context) error                         { return nil }
func (m *mockProvider) Type() idp.ProviderType                                       { return m.provType }
func (m *mockProvider) ID() string                                                   { return m.id }

func (m *mockProvider) SearchUser(ctx context.Context, attr, value string) (string, error) {
	if m.searchFunc != nil {
		return m.searchFunc(ctx, attr, value)
	}
	return "", idp.ErrNotFound
}

func (m *mockProvider) GetUserAttribute(ctx context.Context, userDN, attr string) (string, error) {
	if m.getAttrFunc != nil {
		return m.getAttrFunc(ctx, userDN, attr)
	}
	return "", errors.New("not implemented")
}

// ---------------------------------------------------------------------------
// Mock store
// ---------------------------------------------------------------------------

type mockStore struct {
	enabledIDPs     []db.IdentityProviderRecord
	attrMappings    map[string][]db.AttributeMapping // keyed by IDP ID
	correlationRule map[string]*db.CorrelationRule   // keyed by IDP ID
	mappings        map[string]*db.UserIDPMapping    // keyed by "authProv|authUser|targetIDP"

	upsertedMappings []*db.UserIDPMapping
	verifiedIDs      []int64
	downgradedIDs    []int64

	// Error overrides.
	listIDPsErr              error
	getMappingErr            error
	listAttrMappingsErrFor   map[string]error // keyed by IDP ID
	getCorrelationRuleErr    error
	upsertMappingErr         error
	updateMappingVerifiedErr error
	downgradeMappingErr      error
	deleteCorrelationWarnErr error
}

func newMockStore() *mockStore {
	return &mockStore{
		attrMappings:           make(map[string][]db.AttributeMapping),
		correlationRule:        make(map[string]*db.CorrelationRule),
		mappings:               make(map[string]*db.UserIDPMapping),
		listAttrMappingsErrFor: make(map[string]error),
	}
}

func mappingKey(authProviderID, authUsername, targetIDPID string) string {
	return authProviderID + "|" + authUsername + "|" + targetIDPID
}

func (s *mockStore) ListEnabledIDPs(_ context.Context) ([]db.IdentityProviderRecord, error) {
	if s.listIDPsErr != nil {
		return nil, s.listIDPsErr
	}
	return s.enabledIDPs, nil
}

func (s *mockStore) ListAttributeMappings(_ context.Context, idpID string) ([]db.AttributeMapping, error) {
	if s.listAttrMappingsErrFor != nil {
		if err, ok := s.listAttrMappingsErrFor[idpID]; ok {
			return nil, err
		}
	}
	return s.attrMappings[idpID], nil
}

func (s *mockStore) GetCorrelationRule(_ context.Context, idpID string) (*db.CorrelationRule, error) {
	if s.getCorrelationRuleErr != nil {
		return nil, s.getCorrelationRuleErr
	}
	r, ok := s.correlationRule[idpID]
	if !ok {
		return nil, db.ErrNotFound
	}
	return r, nil
}

func (s *mockStore) GetMapping(_ context.Context, authProviderID, authUsername, targetIDPID string) (*db.UserIDPMapping, error) {
	if s.getMappingErr != nil {
		return nil, s.getMappingErr
	}
	m, ok := s.mappings[mappingKey(authProviderID, authUsername, targetIDPID)]
	if !ok {
		return nil, db.ErrNotFound
	}
	return m, nil
}

func (s *mockStore) HasMappingToTarget(_ context.Context, authUsername, targetIDPID string) (bool, error) {
	for key := range s.mappings {
		// key format: "authProv|authUser|targetIDP"
		parts := strings.SplitN(key, "|", 3)
		if len(parts) == 3 && parts[1] == authUsername && parts[2] == targetIDPID {
			return true, nil
		}
	}
	return false, nil
}

func (s *mockStore) UpsertMapping(_ context.Context, m *db.UserIDPMapping) error {
	if s.upsertMappingErr != nil {
		return s.upsertMappingErr
	}
	s.upsertedMappings = append(s.upsertedMappings, m)
	s.mappings[mappingKey(m.AuthProviderID, m.AuthUsername, m.TargetIDPID)] = m
	return nil
}

func (s *mockStore) UpdateMappingVerified(_ context.Context, id int64, _ time.Time) error {
	s.verifiedIDs = append(s.verifiedIDs, id)
	return s.updateMappingVerifiedErr
}

func (s *mockStore) DowngradeMapping(_ context.Context, id int64) error {
	s.downgradedIDs = append(s.downgradedIDs, id)
	return s.downgradeMappingErr
}

func (s *mockStore) SetCorrelationWarning(_ context.Context, w *db.CorrelationWarning) error {
	return nil
}

func (s *mockStore) DeleteCorrelationWarning(_ context.Context, _, _ string) error {
	return s.deleteCorrelationWarnErr
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func setupEngine(store *mockStore, providers ...idp.Provider) *Engine {
	logger := slog.Default()
	registry := idp.NewRegistry(logger)
	for _, p := range providers {
		registry.Register(p.ID(), p)
	}
	return New(store, registry, logger)
}

const (
	authIDP   = "auth-idp-1"
	targetIDP = "target-idp-1"
	testUser  = "jdoe"
	targetDN  = "CN=jdoe,OU=Users,DC=example,DC=com"
)

func defaultEnabledIDPs() []db.IdentityProviderRecord {
	return []db.IdentityProviderRecord{
		{ID: targetIDP, FriendlyName: "Target AD", ProviderType: "ad", Enabled: true},
	}
}

func defaultRule() *db.CorrelationRule {
	return &db.CorrelationRule{
		IDPID:               targetIDP,
		SourceCanonicalAttr: "email",
		TargetDirectoryAttr: "mail",
		MatchMode:           "exact",
	}
}

func defaultAttrMappings() []db.AttributeMapping {
	return []db.AttributeMapping{
		{IDPID: authIDP, CanonicalName: "email", DirectoryAttr: "mail"},
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestCorrelateUser_NoRuleConfigured_Unlinked(t *testing.T) {
	store := newMockStore()
	store.enabledIDPs = defaultEnabledIDPs()
	// No correlation rule configured for the target IDP.

	authProv := &mockProvider{id: authIDP, provType: idp.ProviderTypeAD}
	targetProv := &mockProvider{id: targetIDP, provType: idp.ProviderTypeAD}

	engine := setupEngine(store, authProv, targetProv)
	results, err := engine.CorrelateUser(context.Background(), authIDP, testUser)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if r.LinkState != LinkStateUnlinked {
		t.Errorf("expected link state %q, got %q", LinkStateUnlinked, r.LinkState)
	}
	if r.AmbiguityWarning {
		t.Error("did not expect ambiguity warning")
	}
	if len(store.upsertedMappings) != 0 {
		t.Error("expected no mappings to be created")
	}
}

func TestCorrelateUser_SingleMatch_LinkedAuto(t *testing.T) {
	store := newMockStore()
	store.enabledIDPs = defaultEnabledIDPs()
	store.correlationRule[targetIDP] = defaultRule()
	store.attrMappings[authIDP] = defaultAttrMappings()

	authProv := &mockProvider{
		id:       authIDP,
		provType: idp.ProviderTypeAD,
		getAttrFunc: func(_ context.Context, _, _ string) (string, error) {
			return "jdoe@example.com", nil
		},
	}
	targetProv := &mockProvider{
		id:       targetIDP,
		provType: idp.ProviderTypeAD,
		searchFunc: func(_ context.Context, attr, value string) (string, error) {
			if attr == "mail" && value == "jdoe@example.com" {
				return targetDN, nil
			}
			return "", idp.ErrNotFound
		},
	}

	engine := setupEngine(store, authProv, targetProv)
	results, err := engine.CorrelateUser(context.Background(), authIDP, testUser)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if r.LinkState != LinkStateLinkedAuto {
		t.Errorf("expected link state %q, got %q", LinkStateLinkedAuto, r.LinkState)
	}
	if r.TargetAccountDN != targetDN {
		t.Errorf("expected target DN %q, got %q", targetDN, r.TargetAccountDN)
	}
	if len(store.upsertedMappings) != 1 {
		t.Fatalf("expected 1 upserted mapping, got %d", len(store.upsertedMappings))
	}
	m := store.upsertedMappings[0]
	if m.LinkType != "auto" {
		t.Errorf("expected link type %q, got %q", "auto", m.LinkType)
	}
	if m.TargetAccountDN != targetDN {
		t.Errorf("expected mapping DN %q, got %q", targetDN, m.TargetAccountDN)
	}
}

func TestCorrelateUser_NoMatch_Unlinked(t *testing.T) {
	store := newMockStore()
	store.enabledIDPs = defaultEnabledIDPs()
	store.correlationRule[targetIDP] = defaultRule()
	store.attrMappings[authIDP] = defaultAttrMappings()

	authProv := &mockProvider{
		id:       authIDP,
		provType: idp.ProviderTypeAD,
		getAttrFunc: func(_ context.Context, _, _ string) (string, error) {
			return "nobody@example.com", nil
		},
	}
	targetProv := &mockProvider{
		id:       targetIDP,
		provType: idp.ProviderTypeAD,
		searchFunc: func(_ context.Context, _, _ string) (string, error) {
			return "", idp.ErrNotFound
		},
	}

	engine := setupEngine(store, authProv, targetProv)
	results, err := engine.CorrelateUser(context.Background(), authIDP, testUser)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	r := results[0]
	if r.LinkState != LinkStateUnlinked {
		t.Errorf("expected %q, got %q", LinkStateUnlinked, r.LinkState)
	}
	if r.AmbiguityWarning {
		t.Error("did not expect ambiguity warning")
	}
}

func TestCorrelateUser_MultipleMatches_UnlinkedWithAmbiguity(t *testing.T) {
	store := newMockStore()
	store.enabledIDPs = defaultEnabledIDPs()
	store.correlationRule[targetIDP] = defaultRule()
	store.attrMappings[authIDP] = defaultAttrMappings()

	authProv := &mockProvider{
		id:       authIDP,
		provType: idp.ProviderTypeAD,
		getAttrFunc: func(_ context.Context, _, _ string) (string, error) {
			return "ambiguous@example.com", nil
		},
	}
	targetProv := &mockProvider{
		id:       targetIDP,
		provType: idp.ProviderTypeAD,
		searchFunc: func(_ context.Context, _, _ string) (string, error) {
			return "", idp.ErrMultipleMatches
		},
	}

	engine := setupEngine(store, authProv, targetProv)
	results, err := engine.CorrelateUser(context.Background(), authIDP, testUser)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	r := results[0]
	if r.LinkState != LinkStateUnlinked {
		t.Errorf("expected %q, got %q", LinkStateUnlinked, r.LinkState)
	}
	if !r.AmbiguityWarning {
		t.Error("expected ambiguity warning")
	}
}

func TestCorrelateUser_ExistingAutoMapping_ReVerified(t *testing.T) {
	store := newMockStore()
	store.enabledIDPs = defaultEnabledIDPs()
	store.correlationRule[targetIDP] = defaultRule()
	store.attrMappings[authIDP] = defaultAttrMappings()

	now := time.Now().UTC()
	store.mappings[mappingKey(authIDP, testUser, targetIDP)] = &db.UserIDPMapping{
		ID:              42,
		AuthProviderID:  authIDP,
		AuthUsername:    testUser,
		TargetIDPID:     targetIDP,
		TargetAccountDN: targetDN,
		LinkType:        "auto",
		LinkedAt:        now.Add(-24 * time.Hour),
		VerifiedAt:      &now,
	}

	authProv := &mockProvider{
		id:       authIDP,
		provType: idp.ProviderTypeAD,
		getAttrFunc: func(_ context.Context, _, _ string) (string, error) {
			return "jdoe@example.com", nil
		},
	}
	targetProv := &mockProvider{
		id:       targetIDP,
		provType: idp.ProviderTypeAD,
		searchFunc: func(_ context.Context, attr, value string) (string, error) {
			if attr == "mail" && value == "jdoe@example.com" {
				return targetDN, nil
			}
			return "", idp.ErrNotFound
		},
	}

	engine := setupEngine(store, authProv, targetProv)
	results, err := engine.CorrelateUser(context.Background(), authIDP, testUser)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	r := results[0]
	if r.LinkState != LinkStateLinkedAuto {
		t.Errorf("expected %q, got %q", LinkStateLinkedAuto, r.LinkState)
	}
	if r.TargetAccountDN != targetDN {
		t.Errorf("expected DN %q, got %q", targetDN, r.TargetAccountDN)
	}
	if len(store.verifiedIDs) != 1 || store.verifiedIDs[0] != 42 {
		t.Errorf("expected verified_at update for mapping 42, got %v", store.verifiedIDs)
	}
	if len(store.downgradedIDs) != 0 {
		t.Error("did not expect downgrade")
	}
}

func TestCorrelateUser_ExistingAutoMapping_VerificationFails_Downgraded(t *testing.T) {
	store := newMockStore()
	store.enabledIDPs = defaultEnabledIDPs()
	store.correlationRule[targetIDP] = defaultRule()
	store.attrMappings[authIDP] = defaultAttrMappings()

	now := time.Now().UTC()
	store.mappings[mappingKey(authIDP, testUser, targetIDP)] = &db.UserIDPMapping{
		ID:              43,
		AuthProviderID:  authIDP,
		AuthUsername:    testUser,
		TargetIDPID:     targetIDP,
		TargetAccountDN: targetDN,
		LinkType:        "auto",
		LinkedAt:        now.Add(-24 * time.Hour),
		VerifiedAt:      &now,
	}

	authProv := &mockProvider{
		id:       authIDP,
		provType: idp.ProviderTypeAD,
		getAttrFunc: func(_ context.Context, _, _ string) (string, error) {
			return "jdoe@example.com", nil
		},
	}
	// Target no longer returns a match.
	targetProv := &mockProvider{
		id:       targetIDP,
		provType: idp.ProviderTypeAD,
		searchFunc: func(_ context.Context, _, _ string) (string, error) {
			return "", idp.ErrNotFound
		},
	}

	engine := setupEngine(store, authProv, targetProv)
	results, err := engine.CorrelateUser(context.Background(), authIDP, testUser)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	r := results[0]
	if r.LinkState != LinkStateUnlinked {
		t.Errorf("expected %q, got %q", LinkStateUnlinked, r.LinkState)
	}
	if len(store.downgradedIDs) != 1 || store.downgradedIDs[0] != 43 {
		t.Errorf("expected downgrade of mapping 43, got %v", store.downgradedIDs)
	}
}

func TestCorrelateUser_ExistingManualMapping_Verified(t *testing.T) {
	store := newMockStore()
	store.enabledIDPs = defaultEnabledIDPs()

	now := time.Now().UTC()
	store.mappings[mappingKey(authIDP, testUser, targetIDP)] = &db.UserIDPMapping{
		ID:              50,
		AuthProviderID:  authIDP,
		AuthUsername:    testUser,
		TargetIDPID:     targetIDP,
		TargetAccountDN: targetDN,
		LinkType:        "manual",
		LinkedAt:        now.Add(-48 * time.Hour),
		VerifiedAt:      &now,
	}

	authProv := &mockProvider{id: authIDP, provType: idp.ProviderTypeAD}
	targetProv := &mockProvider{
		id:       targetIDP,
		provType: idp.ProviderTypeAD,
		searchFunc: func(_ context.Context, attr, value string) (string, error) {
			if attr == "distinguishedName" && value == targetDN {
				return targetDN, nil
			}
			return "", idp.ErrNotFound
		},
	}

	engine := setupEngine(store, authProv, targetProv)
	results, err := engine.CorrelateUser(context.Background(), authIDP, testUser)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	r := results[0]
	if r.LinkState != LinkStateLinkedManual {
		t.Errorf("expected %q, got %q", LinkStateLinkedManual, r.LinkState)
	}
	if r.TargetAccountDN != targetDN {
		t.Errorf("expected DN %q, got %q", targetDN, r.TargetAccountDN)
	}
	if len(store.verifiedIDs) != 1 || store.verifiedIDs[0] != 50 {
		t.Errorf("expected verified_at update for mapping 50, got %v", store.verifiedIDs)
	}
}

func TestCorrelateUser_ExistingManualMapping_VerificationFails_Downgraded(t *testing.T) {
	store := newMockStore()
	store.enabledIDPs = defaultEnabledIDPs()

	now := time.Now().UTC()
	store.mappings[mappingKey(authIDP, testUser, targetIDP)] = &db.UserIDPMapping{
		ID:              51,
		AuthProviderID:  authIDP,
		AuthUsername:    testUser,
		TargetIDPID:     targetIDP,
		TargetAccountDN: targetDN,
		LinkType:        "manual",
		LinkedAt:        now.Add(-48 * time.Hour),
		VerifiedAt:      &now,
	}

	authProv := &mockProvider{id: authIDP, provType: idp.ProviderTypeAD}
	// Target DN no longer exists.
	targetProv := &mockProvider{
		id:       targetIDP,
		provType: idp.ProviderTypeAD,
		searchFunc: func(_ context.Context, _, _ string) (string, error) {
			return "", idp.ErrNotFound
		},
	}

	engine := setupEngine(store, authProv, targetProv)
	results, err := engine.CorrelateUser(context.Background(), authIDP, testUser)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	r := results[0]
	if r.LinkState != LinkStateUnlinked {
		t.Errorf("expected %q, got %q", LinkStateUnlinked, r.LinkState)
	}
	if len(store.downgradedIDs) != 1 || store.downgradedIDs[0] != 51 {
		t.Errorf("expected downgrade of mapping 51, got %v", store.downgradedIDs)
	}
}

func TestCorrelateUser_ProviderUnreachable_UnlinkedNocrash(t *testing.T) {
	store := newMockStore()
	store.enabledIDPs = defaultEnabledIDPs()
	store.correlationRule[targetIDP] = defaultRule()
	store.attrMappings[authIDP] = defaultAttrMappings()

	authProv := &mockProvider{
		id:       authIDP,
		provType: idp.ProviderTypeAD,
		getAttrFunc: func(_ context.Context, _, _ string) (string, error) {
			return "jdoe@example.com", nil
		},
	}
	// Target provider returns a connection error (not ErrNotFound or ErrMultipleMatches).
	targetProv := &mockProvider{
		id:       targetIDP,
		provType: idp.ProviderTypeAD,
		searchFunc: func(_ context.Context, _, _ string) (string, error) {
			return "", errors.New("connection refused")
		},
	}

	engine := setupEngine(store, authProv, targetProv)
	results, err := engine.CorrelateUser(context.Background(), authIDP, testUser)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if r.LinkState != LinkStateUnlinked {
		t.Errorf("expected %q, got %q", LinkStateUnlinked, r.LinkState)
	}
}

func TestCorrelateUser_ProviderNotInRegistry_UnlinkedNocrash(t *testing.T) {
	store := newMockStore()
	store.enabledIDPs = defaultEnabledIDPs()
	store.correlationRule[targetIDP] = defaultRule()
	store.attrMappings[authIDP] = defaultAttrMappings()

	// Auth provider is registered but target is NOT in the registry.
	authProv := &mockProvider{
		id:       authIDP,
		provType: idp.ProviderTypeAD,
		getAttrFunc: func(_ context.Context, _, _ string) (string, error) {
			return "jdoe@example.com", nil
		},
	}

	engine := setupEngine(store, authProv) // only auth provider registered
	results, err := engine.CorrelateUser(context.Background(), authIDP, testUser)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if r.LinkState != LinkStateUnlinked {
		t.Errorf("expected %q, got %q", LinkStateUnlinked, r.LinkState)
	}
}

func TestResolveCanonicalAttribute_Success(t *testing.T) {
	store := newMockStore()
	store.attrMappings[authIDP] = defaultAttrMappings()

	authProv := &mockProvider{
		id:       authIDP,
		provType: idp.ProviderTypeAD,
		getAttrFunc: func(_ context.Context, userDN, attr string) (string, error) {
			if userDN == testUser && attr == "mail" {
				return "jdoe@example.com", nil
			}
			return "", errors.New("unexpected call")
		},
	}

	engine := setupEngine(store, authProv)
	val, err := engine.ResolveCanonicalAttribute(context.Background(), authIDP, testUser, "email")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != "jdoe@example.com" {
		t.Errorf("expected %q, got %q", "jdoe@example.com", val)
	}
}

func TestResolveCanonicalAttribute_NoMapping(t *testing.T) {
	store := newMockStore()
	// No attribute mappings configured.

	authProv := &mockProvider{id: authIDP, provType: idp.ProviderTypeAD}
	engine := setupEngine(store, authProv)

	_, err := engine.ResolveCanonicalAttribute(context.Background(), authIDP, testUser, "email")
	if err == nil {
		t.Fatal("expected error for missing attribute mapping")
	}
}

func TestCorrelateUser_MultipleIDPs(t *testing.T) {
	const targetIDP2 = "target-idp-2"
	const targetDN2 = "uid=jdoe,ou=People,dc=example,dc=com"

	store := newMockStore()
	store.enabledIDPs = []db.IdentityProviderRecord{
		{ID: targetIDP, FriendlyName: "Target AD", ProviderType: "ad", Enabled: true},
		{ID: targetIDP2, FriendlyName: "Target FreeIPA", ProviderType: "freeipa", Enabled: true},
	}
	store.correlationRule[targetIDP] = defaultRule()
	store.correlationRule[targetIDP2] = &db.CorrelationRule{
		IDPID:               targetIDP2,
		SourceCanonicalAttr: "email",
		TargetDirectoryAttr: "mail",
		MatchMode:           "exact",
	}
	store.attrMappings[authIDP] = defaultAttrMappings()

	authProv := &mockProvider{
		id:       authIDP,
		provType: idp.ProviderTypeAD,
		getAttrFunc: func(_ context.Context, _, _ string) (string, error) {
			return "jdoe@example.com", nil
		},
	}
	targetProv1 := &mockProvider{
		id:       targetIDP,
		provType: idp.ProviderTypeAD,
		searchFunc: func(_ context.Context, _, _ string) (string, error) {
			return targetDN, nil
		},
	}
	targetProv2 := &mockProvider{
		id:       targetIDP2,
		provType: idp.ProviderTypeFreeIPA,
		searchFunc: func(_ context.Context, _, _ string) (string, error) {
			return targetDN2, nil
		},
	}

	engine := setupEngine(store, authProv, targetProv1, targetProv2)
	results, err := engine.CorrelateUser(context.Background(), authIDP, testUser)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	linked := 0
	for _, r := range results {
		if r.LinkState == LinkStateLinkedAuto {
			linked++
		}
	}
	if linked != 2 {
		t.Errorf("expected 2 linked results, got %d", linked)
	}
}

func TestVerifyAutoMapping_DNChanged_Downgraded(t *testing.T) {
	// Existing auto mapping holds targetDN, but the LDAP search now returns a different DN.
	// The engine should downgrade the mapping and return unlinked.
	const differentDN = "CN=jdoe_renamed,OU=Users,DC=example,DC=com"

	store := newMockStore()
	store.enabledIDPs = defaultEnabledIDPs()
	store.correlationRule[targetIDP] = defaultRule()
	store.attrMappings[authIDP] = defaultAttrMappings()

	now := time.Now().UTC()
	store.mappings[mappingKey(authIDP, testUser, targetIDP)] = &db.UserIDPMapping{
		ID:              77,
		AuthProviderID:  authIDP,
		AuthUsername:    testUser,
		TargetIDPID:     targetIDP,
		TargetAccountDN: targetDN,
		LinkType:        "auto",
		LinkedAt:        now.Add(-24 * time.Hour),
		VerifiedAt:      &now,
	}

	authProv := &mockProvider{
		id:       authIDP,
		provType: idp.ProviderTypeAD,
		getAttrFunc: func(_ context.Context, _, _ string) (string, error) {
			return "jdoe@example.com", nil
		},
	}
	targetProv := &mockProvider{
		id:       targetIDP,
		provType: idp.ProviderTypeAD,
		// Returns a DN that differs from the stored targetDN.
		searchFunc: func(_ context.Context, _, _ string) (string, error) {
			return differentDN, nil
		},
	}

	engine := setupEngine(store, authProv, targetProv)
	results, err := engine.CorrelateUser(context.Background(), authIDP, testUser)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if r.LinkState != LinkStateUnlinked {
		t.Errorf("expected %q (DN changed → downgrade), got %q", LinkStateUnlinked, r.LinkState)
	}
	if len(store.downgradedIDs) != 1 || store.downgradedIDs[0] != 77 {
		t.Errorf("expected downgrade of mapping 77, got %v", store.downgradedIDs)
	}
}

func TestVerifyAutoMapping_RuleDeleted_Downgraded(t *testing.T) {
	// Existing auto mapping but the correlation rule has since been deleted.
	// verifyAutoMapping receives ErrNotFound from GetCorrelationRule and must downgrade.
	store := newMockStore()
	store.enabledIDPs = defaultEnabledIDPs()
	// Deliberately do NOT set store.correlationRule[targetIDP] — simulates a deleted rule.
	store.attrMappings[authIDP] = defaultAttrMappings()

	now := time.Now().UTC()
	store.mappings[mappingKey(authIDP, testUser, targetIDP)] = &db.UserIDPMapping{
		ID:              88,
		AuthProviderID:  authIDP,
		AuthUsername:    testUser,
		TargetIDPID:     targetIDP,
		TargetAccountDN: targetDN,
		LinkType:        "auto",
		LinkedAt:        now.Add(-24 * time.Hour),
		VerifiedAt:      &now,
	}

	authProv := &mockProvider{id: authIDP, provType: idp.ProviderTypeAD}
	targetProv := &mockProvider{id: targetIDP, provType: idp.ProviderTypeAD}

	engine := setupEngine(store, authProv, targetProv)
	results, err := engine.CorrelateUser(context.Background(), authIDP, testUser)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if r.LinkState != LinkStateUnlinked {
		t.Errorf("expected %q (rule deleted → downgrade), got %q", LinkStateUnlinked, r.LinkState)
	}
	if len(store.downgradedIDs) != 1 || store.downgradedIDs[0] != 88 {
		t.Errorf("expected downgrade of mapping 88, got %v", store.downgradedIDs)
	}
}

func TestResolveTargetDirectoryAttr_ExplicitFallback(t *testing.T) {
	// No attribute mapping on the target IDP for the canonical name, but the
	// correlation rule has an explicit TargetDirectoryAttr set — that should be used.
	store := newMockStore()
	store.enabledIDPs = defaultEnabledIDPs()
	// Rule with explicit TargetDirectoryAttr and no attr mapping on the target IDP.
	store.correlationRule[targetIDP] = &db.CorrelationRule{
		IDPID:               targetIDP,
		SourceCanonicalAttr: "email",
		TargetDirectoryAttr: "userPrincipalName", // explicit attr
		MatchMode:           "exact",
	}
	store.attrMappings[authIDP] = defaultAttrMappings()
	// store.attrMappings[targetIDP] intentionally empty → no target mapping

	authProv := &mockProvider{
		id:       authIDP,
		provType: idp.ProviderTypeAD,
		getAttrFunc: func(_ context.Context, _, _ string) (string, error) {
			return "jdoe@example.com", nil
		},
	}
	var capturedAttr string
	targetProv := &mockProvider{
		id:       targetIDP,
		provType: idp.ProviderTypeAD,
		searchFunc: func(_ context.Context, attr, value string) (string, error) {
			capturedAttr = attr
			if value == "jdoe@example.com" {
				return targetDN, nil
			}
			return "", idp.ErrNotFound
		},
	}

	engine := setupEngine(store, authProv, targetProv)
	results, err := engine.CorrelateUser(context.Background(), authIDP, testUser)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if r.LinkState != LinkStateLinkedAuto {
		t.Errorf("expected %q, got %q", LinkStateLinkedAuto, r.LinkState)
	}
	// Verify that the explicit attr (not a mapping-derived attr) was used for the search.
	if capturedAttr != "userPrincipalName" {
		t.Errorf("expected search attr %q (explicit fallback), got %q", "userPrincipalName", capturedAttr)
	}
}

func TestResolveTargetDirectoryAttr_NoMappingNoExplicit_Error(t *testing.T) {
	// Neither a target attribute mapping nor an explicit TargetDirectoryAttr is set.
	// resolveTargetDirectoryAttr must return an error, causing the correlation to fail
	// and the result to be unlinked.
	store := newMockStore()
	store.enabledIDPs = defaultEnabledIDPs()
	store.correlationRule[targetIDP] = &db.CorrelationRule{
		IDPID:               targetIDP,
		SourceCanonicalAttr: "email",
		TargetDirectoryAttr: "", // explicitly empty — no fallback
		MatchMode:           "exact",
	}
	store.attrMappings[authIDP] = defaultAttrMappings()
	// store.attrMappings[targetIDP] intentionally empty

	authProv := &mockProvider{
		id:       authIDP,
		provType: idp.ProviderTypeAD,
		getAttrFunc: func(_ context.Context, _, _ string) (string, error) {
			return "jdoe@example.com", nil
		},
	}
	targetProv := &mockProvider{id: targetIDP, provType: idp.ProviderTypeAD}

	engine := setupEngine(store, authProv, targetProv)
	results, err := engine.CorrelateUser(context.Background(), authIDP, testUser)
	if err != nil {
		t.Fatalf("unexpected top-level error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	// The error from resolveTargetDirectoryAttr causes correlateForTarget to return an
	// error, which CorrelateUser treats as an unlinked result.
	r := results[0]
	if r.LinkState != LinkStateUnlinked {
		t.Errorf("expected %q (no attr → error → unlinked), got %q", LinkStateUnlinked, r.LinkState)
	}
}

func TestVerifyExistingMapping_UnknownLinkType_Error(t *testing.T) {
	// An existing mapping with an unrecognised LinkType must not crash; the engine
	// logs the error and returns the IDP as unlinked.
	store := newMockStore()
	store.enabledIDPs = defaultEnabledIDPs()

	now := time.Now().UTC()
	store.mappings[mappingKey(authIDP, testUser, targetIDP)] = &db.UserIDPMapping{
		ID:              55,
		AuthProviderID:  authIDP,
		AuthUsername:    testUser,
		TargetIDPID:     targetIDP,
		TargetAccountDN: targetDN,
		LinkType:        "unknown_type", // invalid
		LinkedAt:        now.Add(-24 * time.Hour),
		VerifiedAt:      &now,
	}

	authProv := &mockProvider{id: authIDP, provType: idp.ProviderTypeAD}
	targetProv := &mockProvider{id: targetIDP, provType: idp.ProviderTypeAD}

	engine := setupEngine(store, authProv, targetProv)
	results, err := engine.CorrelateUser(context.Background(), authIDP, testUser)
	if err != nil {
		t.Fatalf("unexpected top-level error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if r.LinkState != LinkStateUnlinked {
		t.Errorf("expected %q for unknown link type, got %q", LinkStateUnlinked, r.LinkState)
	}
}

func TestVerifyAutoMapping_MultipleMatches_Downgraded(t *testing.T) {
	// During re-verification, if the search returns ErrMultipleMatches, the mapping
	// is downgraded and AmbiguityWarning is set.
	store := newMockStore()
	store.enabledIDPs = defaultEnabledIDPs()
	store.correlationRule[targetIDP] = defaultRule()
	store.attrMappings[authIDP] = defaultAttrMappings()

	now := time.Now().UTC()
	store.mappings[mappingKey(authIDP, testUser, targetIDP)] = &db.UserIDPMapping{
		ID:              60,
		AuthProviderID:  authIDP,
		AuthUsername:    testUser,
		TargetIDPID:     targetIDP,
		TargetAccountDN: targetDN,
		LinkType:        "auto",
		LinkedAt:        now.Add(-24 * time.Hour),
		VerifiedAt:      &now,
	}

	authProv := &mockProvider{
		id:       authIDP,
		provType: idp.ProviderTypeAD,
		getAttrFunc: func(_ context.Context, _, _ string) (string, error) {
			return "jdoe@example.com", nil
		},
	}
	targetProv := &mockProvider{
		id:       targetIDP,
		provType: idp.ProviderTypeAD,
		searchFunc: func(_ context.Context, _, _ string) (string, error) {
			return "", idp.ErrMultipleMatches
		},
	}

	engine := setupEngine(store, authProv, targetProv)
	results, err := engine.CorrelateUser(context.Background(), authIDP, testUser)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	r := results[0]
	if r.LinkState != LinkStateUnlinked {
		t.Errorf("expected %q, got %q", LinkStateUnlinked, r.LinkState)
	}
	if !r.AmbiguityWarning {
		t.Error("expected AmbiguityWarning=true for multiple matches during re-verification")
	}
	if len(store.downgradedIDs) != 1 || store.downgradedIDs[0] != 60 {
		t.Errorf("expected downgrade of mapping 60, got %v", store.downgradedIDs)
	}
}

func TestCorrelateUser_ListIDPsError(t *testing.T) {
	store := newMockStore()
	store.listIDPsErr = errors.New("database unavailable")

	engine := setupEngine(store)
	_, err := engine.CorrelateUser(context.Background(), authIDP, testUser)
	if err == nil {
		t.Fatal("expected error when ListEnabledIDPs fails")
	}
}

func TestCorrelateUser_SelfMappingPreserved(t *testing.T) {
	// A self-mapping (auth_provider == target_idp) should NOT be downgraded
	// even when no correlation rule is configured for the target IDP.
	store := newMockStore()
	store.enabledIDPs = []db.IdentityProviderRecord{
		{ID: authIDP, FriendlyName: "Auth AD", ProviderType: "ad", Enabled: true},
	}
	// No correlation rule configured for authIDP.

	now := time.Now().UTC()
	selfMapping := &db.UserIDPMapping{
		ID:              99,
		AuthProviderID:  authIDP,
		AuthUsername:    testUser,
		TargetIDPID:     authIDP, // self-mapping: auth == target
		TargetAccountDN: "CN=jdoe,OU=Users,DC=auth,DC=com",
		LinkType:        "auto",
		LinkedAt:        now.Add(-24 * time.Hour),
		VerifiedAt:      &now,
	}
	store.mappings[mappingKey(authIDP, testUser, authIDP)] = selfMapping

	authProv := &mockProvider{id: authIDP, provType: idp.ProviderTypeAD}

	engine := setupEngine(store, authProv)
	results, err := engine.CorrelateUser(context.Background(), authIDP, testUser)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Find the result for the self-mapping IDP.
	var selfResult *MappingResult
	for i := range results {
		if results[i].IDPID == authIDP {
			selfResult = &results[i]
			break
		}
	}
	if selfResult == nil {
		t.Fatal("expected a result for the auth IDP (self-mapping)")
	}

	// The self-mapping should remain linked, not downgraded.
	if selfResult.LinkState != LinkStateLinkedAuto {
		t.Errorf("expected link state %q for self-mapping, got %q", LinkStateLinkedAuto, selfResult.LinkState)
	}
	if selfResult.TargetAccountDN != selfMapping.TargetAccountDN {
		t.Errorf("expected DN %q, got %q", selfMapping.TargetAccountDN, selfResult.TargetAccountDN)
	}

	// Verify it was re-verified, not downgraded.
	if len(store.verifiedIDs) != 1 || store.verifiedIDs[0] != 99 {
		t.Errorf("expected verified_at update for mapping 99, got %v", store.verifiedIDs)
	}
	if len(store.downgradedIDs) != 0 {
		t.Errorf("expected no downgrades for self-mapping, got %v", store.downgradedIDs)
	}
}

// ---------------------------------------------------------------------------
// Additional tests for uncovered paths
// ---------------------------------------------------------------------------

// TestCorrelateForTarget_GetMappingError covers the non-ErrNotFound GetMapping
// error path in correlateForTarget (engine.go:131-133).
func TestCorrelateForTarget_GetMappingError(t *testing.T) {
	store := newMockStore()
	store.enabledIDPs = defaultEnabledIDPs()
	store.getMappingErr = errors.New("database connection lost")

	authProv := &mockProvider{id: authIDP, provType: idp.ProviderTypeAD}
	targetProv := &mockProvider{id: targetIDP, provType: idp.ProviderTypeAD}
	engine := setupEngine(store, authProv, targetProv)

	results, err := engine.CorrelateUser(context.Background(), authIDP, testUser)
	if err != nil {
		t.Fatalf("unexpected top-level error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].LinkState != LinkStateUnlinked {
		t.Errorf("expected %q for GetMapping error, got %q", LinkStateUnlinked, results[0].LinkState)
	}
}

// TestVerifyExistingMapping_ProviderNotInRegistry covers engine.go:146-148 —
// an existing mapping but the target provider is not registered.
func TestVerifyExistingMapping_ProviderNotInRegistry(t *testing.T) {
	store := newMockStore()
	store.enabledIDPs = defaultEnabledIDPs()

	now := time.Now().UTC()
	store.mappings[mappingKey(authIDP, testUser, targetIDP)] = &db.UserIDPMapping{
		ID:              90,
		AuthProviderID:  authIDP,
		AuthUsername:    testUser,
		TargetIDPID:     targetIDP,
		TargetAccountDN: targetDN,
		LinkType:        "manual",
		LinkedAt:        now.Add(-24 * time.Hour),
		VerifiedAt:      &now,
	}

	// Only auth provider is registered; target is NOT.
	authProv := &mockProvider{id: authIDP, provType: idp.ProviderTypeAD}
	engine := setupEngine(store, authProv)

	results, err := engine.CorrelateUser(context.Background(), authIDP, testUser)
	if err != nil {
		t.Fatalf("unexpected top-level error: %v", err)
	}
	if results[0].LinkState != LinkStateUnlinked {
		t.Errorf("expected %q when provider not in registry, got %q", LinkStateUnlinked, results[0].LinkState)
	}
}

// TestVerifyManualMapping_DowngradeFails covers the DowngradeMapping error
// path in verifyManualMapping (engine.go:182-184).
func TestVerifyManualMapping_DowngradeFails(t *testing.T) {
	store := newMockStore()
	store.enabledIDPs = defaultEnabledIDPs()
	store.downgradeMappingErr = errors.New("downgrade failed: disk full")

	now := time.Now().UTC()
	store.mappings[mappingKey(authIDP, testUser, targetIDP)] = &db.UserIDPMapping{
		ID:              51,
		AuthProviderID:  authIDP,
		AuthUsername:    testUser,
		TargetIDPID:     targetIDP,
		TargetAccountDN: targetDN,
		LinkType:        "manual",
		LinkedAt:        now.Add(-48 * time.Hour),
		VerifiedAt:      &now,
	}

	authProv := &mockProvider{id: authIDP, provType: idp.ProviderTypeAD}
	// Target DN no longer exists → triggers downgrade.
	targetProv := &mockProvider{
		id:       targetIDP,
		provType: idp.ProviderTypeAD,
		searchFunc: func(_ context.Context, _, _ string) (string, error) {
			return "", idp.ErrNotFound
		},
	}

	engine := setupEngine(store, authProv, targetProv)
	// DowngradeMapping returns an error, which propagates through correlateForTarget
	// to CorrelateUser, which logs it and produces an unlinked result.
	results, err := engine.CorrelateUser(context.Background(), authIDP, testUser)
	if err != nil {
		t.Fatalf("unexpected top-level error: %v", err)
	}
	if results[0].LinkState != LinkStateUnlinked {
		t.Errorf("expected %q when downgrade fails, got %q", LinkStateUnlinked, results[0].LinkState)
	}
}

// TestVerifyAutoMapping_GetCorrelationRuleError covers the non-ErrNotFound
// GetCorrelationRule error in verifyAutoMapping (engine.go:221).
func TestVerifyAutoMapping_GetCorrelationRuleError(t *testing.T) {
	store := newMockStore()
	store.enabledIDPs = defaultEnabledIDPs()
	store.getCorrelationRuleErr = errors.New("db timeout")

	now := time.Now().UTC()
	store.mappings[mappingKey(authIDP, testUser, targetIDP)] = &db.UserIDPMapping{
		ID:              72,
		AuthProviderID:  authIDP,
		AuthUsername:    testUser,
		TargetIDPID:     targetIDP,
		TargetAccountDN: targetDN,
		LinkType:        "auto",
		LinkedAt:        now.Add(-24 * time.Hour),
		VerifiedAt:      &now,
	}

	authProv := &mockProvider{id: authIDP, provType: idp.ProviderTypeAD}
	targetProv := &mockProvider{id: targetIDP, provType: idp.ProviderTypeAD}
	engine := setupEngine(store, authProv, targetProv)

	results, err := engine.CorrelateUser(context.Background(), authIDP, testUser)
	if err != nil {
		t.Fatalf("unexpected top-level error: %v", err)
	}
	if results[0].LinkState != LinkStateUnlinked {
		t.Errorf("expected %q for rule fetch error, got %q", LinkStateUnlinked, results[0].LinkState)
	}
}

// TestVerifyAutoMapping_CanonicalResolveFails_Downgraded covers
// engine.go:226-231 — ResolveCanonicalAttribute fails in verifyAutoMapping.
func TestVerifyAutoMapping_CanonicalResolveFails_Downgraded(t *testing.T) {
	store := newMockStore()
	store.enabledIDPs = defaultEnabledIDPs()
	store.correlationRule[targetIDP] = defaultRule()
	// No attrMappings for authIDP → ResolveCanonicalAttribute returns error.

	now := time.Now().UTC()
	store.mappings[mappingKey(authIDP, testUser, targetIDP)] = &db.UserIDPMapping{
		ID:              70,
		AuthProviderID:  authIDP,
		AuthUsername:    testUser,
		TargetIDPID:     targetIDP,
		TargetAccountDN: targetDN,
		LinkType:        "auto",
		LinkedAt:        now.Add(-24 * time.Hour),
		VerifiedAt:      &now,
	}

	authProv := &mockProvider{id: authIDP, provType: idp.ProviderTypeAD}
	targetProv := &mockProvider{id: targetIDP, provType: idp.ProviderTypeAD}
	engine := setupEngine(store, authProv, targetProv)

	results, err := engine.CorrelateUser(context.Background(), authIDP, testUser)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if results[0].LinkState != LinkStateUnlinked {
		t.Errorf("expected %q (resolve failed → downgrade), got %q", LinkStateUnlinked, results[0].LinkState)
	}
	if len(store.downgradedIDs) != 1 || store.downgradedIDs[0] != 70 {
		t.Errorf("expected downgrade of mapping 70, got %v", store.downgradedIDs)
	}
}

// TestVerifyAutoMapping_TargetAttrResolveFails_Downgraded covers
// engine.go:235-239 — resolveTargetDirectoryAttr fails in verifyAutoMapping.
func TestVerifyAutoMapping_TargetAttrResolveFails_Downgraded(t *testing.T) {
	store := newMockStore()
	store.enabledIDPs = defaultEnabledIDPs()
	store.correlationRule[targetIDP] = &db.CorrelationRule{
		IDPID:               targetIDP,
		SourceCanonicalAttr: "email",
		TargetDirectoryAttr: "", // no fallback
		MatchMode:           "exact",
	}
	store.attrMappings[authIDP] = defaultAttrMappings()
	// No attrMappings[targetIDP] and empty TargetDirectoryAttr →
	// resolveTargetDirectoryAttr returns error.

	now := time.Now().UTC()
	store.mappings[mappingKey(authIDP, testUser, targetIDP)] = &db.UserIDPMapping{
		ID:              71,
		AuthProviderID:  authIDP,
		AuthUsername:    testUser,
		TargetIDPID:     targetIDP,
		TargetAccountDN: targetDN,
		LinkType:        "auto",
		LinkedAt:        now.Add(-24 * time.Hour),
		VerifiedAt:      &now,
	}

	authProv := &mockProvider{
		id:       authIDP,
		provType: idp.ProviderTypeAD,
		getAttrFunc: func(_ context.Context, _, _ string) (string, error) {
			return "jdoe@example.com", nil
		},
	}
	targetProv := &mockProvider{id: targetIDP, provType: idp.ProviderTypeAD}
	engine := setupEngine(store, authProv, targetProv)

	results, err := engine.CorrelateUser(context.Background(), authIDP, testUser)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if results[0].LinkState != LinkStateUnlinked {
		t.Errorf("expected %q (target attr resolve failed → downgrade), got %q", LinkStateUnlinked, results[0].LinkState)
	}
	if len(store.downgradedIDs) != 1 || store.downgradedIDs[0] != 71 {
		t.Errorf("expected downgrade of mapping 71, got %v", store.downgradedIDs)
	}
}

// TestAttemptAutoCorrelation_GetCorrelationRuleError covers
// engine.go:285 — non-ErrNotFound error from GetCorrelationRule in
// attemptAutoCorrelation.
func TestAttemptAutoCorrelation_GetCorrelationRuleError(t *testing.T) {
	store := newMockStore()
	store.enabledIDPs = defaultEnabledIDPs()
	store.getCorrelationRuleErr = errors.New("db timeout")
	// No existing mapping → will call attemptAutoCorrelation.

	authProv := &mockProvider{id: authIDP, provType: idp.ProviderTypeAD}
	targetProv := &mockProvider{id: targetIDP, provType: idp.ProviderTypeAD}
	engine := setupEngine(store, authProv, targetProv)

	results, err := engine.CorrelateUser(context.Background(), authIDP, testUser)
	if err != nil {
		t.Fatalf("unexpected top-level error: %v", err)
	}
	if results[0].LinkState != LinkStateUnlinked {
		t.Errorf("expected %q for rule fetch error, got %q", LinkStateUnlinked, results[0].LinkState)
	}
}

// TestAttemptAutoCorrelation_CanonicalResolveFails covers engine.go:296-303 —
// ResolveCanonicalAttribute fails in attemptAutoCorrelation.
func TestAttemptAutoCorrelation_CanonicalResolveFails(t *testing.T) {
	store := newMockStore()
	store.enabledIDPs = defaultEnabledIDPs()
	store.correlationRule[targetIDP] = defaultRule()
	// No attrMappings for authIDP → ResolveCanonicalAttribute returns error.
	// No existing mapping → reaches attemptAutoCorrelation.

	authProv := &mockProvider{id: authIDP, provType: idp.ProviderTypeAD}
	targetProv := &mockProvider{id: targetIDP, provType: idp.ProviderTypeAD}
	engine := setupEngine(store, authProv, targetProv)

	results, err := engine.CorrelateUser(context.Background(), authIDP, testUser)
	if err != nil {
		t.Fatalf("unexpected top-level error: %v", err)
	}
	if results[0].LinkState != LinkStateUnlinked {
		t.Errorf("expected %q for canonical resolve failure, got %q", LinkStateUnlinked, results[0].LinkState)
	}
}

// TestAttemptAutoCorrelation_MappingAlreadyExists covers engine.go:359-367 —
// HasMappingToTarget returns true (another auth provider already has a mapping
// to this target IDP for the same username).
func TestAttemptAutoCorrelation_MappingAlreadyExists(t *testing.T) {
	store := newMockStore()
	store.enabledIDPs = defaultEnabledIDPs()
	store.correlationRule[targetIDP] = defaultRule()
	store.attrMappings[authIDP] = defaultAttrMappings()

	// A mapping from a DIFFERENT auth provider to the same target already exists.
	// HasMappingToTarget searches by (authUsername, targetIDP) regardless of authProvider.
	store.mappings[mappingKey("other-idp", testUser, targetIDP)] = &db.UserIDPMapping{
		ID:              100,
		AuthProviderID:  "other-idp",
		AuthUsername:    testUser,
		TargetIDPID:     targetIDP,
		TargetAccountDN: targetDN,
		LinkType:        "auto",
	}

	authProv := &mockProvider{
		id:       authIDP,
		provType: idp.ProviderTypeAD,
		getAttrFunc: func(_ context.Context, _, _ string) (string, error) {
			return "jdoe@example.com", nil
		},
	}
	targetProv := &mockProvider{
		id:       targetIDP,
		provType: idp.ProviderTypeAD,
		searchFunc: func(_ context.Context, _, _ string) (string, error) {
			return targetDN, nil
		},
	}
	engine := setupEngine(store, authProv, targetProv)

	results, err := engine.CorrelateUser(context.Background(), authIDP, testUser)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if results[0].LinkState != LinkStateLinkedAuto {
		t.Errorf("expected %q when mapping already exists, got %q", LinkStateLinkedAuto, results[0].LinkState)
	}
	// No new mapping should have been upserted.
	if len(store.upsertedMappings) != 0 {
		t.Errorf("expected no new upserted mappings, got %d", len(store.upsertedMappings))
	}
}

// TestAttemptAutoCorrelation_UpsertError covers engine.go:387-389 — the
// UpsertMapping error path.
func TestAttemptAutoCorrelation_UpsertError(t *testing.T) {
	store := newMockStore()
	store.enabledIDPs = defaultEnabledIDPs()
	store.correlationRule[targetIDP] = defaultRule()
	store.attrMappings[authIDP] = defaultAttrMappings()
	store.upsertMappingErr = errors.New("upsert failed: disk full")

	authProv := &mockProvider{
		id:       authIDP,
		provType: idp.ProviderTypeAD,
		getAttrFunc: func(_ context.Context, _, _ string) (string, error) {
			return "jdoe@example.com", nil
		},
	}
	targetProv := &mockProvider{
		id:       targetIDP,
		provType: idp.ProviderTypeAD,
		searchFunc: func(_ context.Context, _, _ string) (string, error) {
			return targetDN, nil
		},
	}
	engine := setupEngine(store, authProv, targetProv)

	results, err := engine.CorrelateUser(context.Background(), authIDP, testUser)
	if err != nil {
		t.Fatalf("unexpected top-level error: %v", err)
	}
	// UpsertMapping error causes correlateForTarget to return error →
	// CorrelateUser produces unlinked result.
	if results[0].LinkState != LinkStateUnlinked {
		t.Errorf("expected %q for upsert error, got %q", LinkStateUnlinked, results[0].LinkState)
	}
}

// TestResolveTargetDirectoryAttr_ListMappingsError covers engine.go:404-406 —
// ListAttributeMappings returns an error inside resolveTargetDirectoryAttr.
func TestResolveTargetDirectoryAttr_ListMappingsError(t *testing.T) {
	store := newMockStore()
	store.enabledIDPs = defaultEnabledIDPs()
	store.correlationRule[targetIDP] = defaultRule()
	store.attrMappings[authIDP] = defaultAttrMappings()
	store.listAttrMappingsErrFor[targetIDP] = errors.New("db error for target IDP")

	authProv := &mockProvider{
		id:       authIDP,
		provType: idp.ProviderTypeAD,
		getAttrFunc: func(_ context.Context, _, _ string) (string, error) {
			return "jdoe@example.com", nil
		},
	}
	targetProv := &mockProvider{id: targetIDP, provType: idp.ProviderTypeAD}
	engine := setupEngine(store, authProv, targetProv)

	results, err := engine.CorrelateUser(context.Background(), authIDP, testUser)
	if err != nil {
		t.Fatalf("unexpected top-level error: %v", err)
	}
	if results[0].LinkState != LinkStateUnlinked {
		t.Errorf("expected %q for ListAttributeMappings error, got %q", LinkStateUnlinked, results[0].LinkState)
	}
}

// TestResolveTargetDirectoryAttr_ViaTargetMapping covers engine.go:408-416 —
// the target IDP has its own attribute mapping for the canonical name.
func TestResolveTargetDirectoryAttr_ViaTargetMapping(t *testing.T) {
	store := newMockStore()
	store.enabledIDPs = defaultEnabledIDPs()
	store.correlationRule[targetIDP] = &db.CorrelationRule{
		IDPID:               targetIDP,
		SourceCanonicalAttr: "email",
		TargetDirectoryAttr: "mail", // fallback if no target mapping
		MatchMode:           "exact",
	}
	store.attrMappings[authIDP] = defaultAttrMappings()
	// Target IDP has its own mapping: canonical "email" → "userPrincipalName".
	store.attrMappings[targetIDP] = []db.AttributeMapping{
		{IDPID: targetIDP, CanonicalName: "email", DirectoryAttr: "userPrincipalName"},
	}

	var capturedAttr string
	authProv := &mockProvider{
		id:       authIDP,
		provType: idp.ProviderTypeAD,
		getAttrFunc: func(_ context.Context, _, _ string) (string, error) {
			return "jdoe@example.com", nil
		},
	}
	targetProv := &mockProvider{
		id:       targetIDP,
		provType: idp.ProviderTypeAD,
		searchFunc: func(_ context.Context, attr, value string) (string, error) {
			capturedAttr = attr
			if value == "jdoe@example.com" {
				return targetDN, nil
			}
			return "", idp.ErrNotFound
		},
	}
	engine := setupEngine(store, authProv, targetProv)

	results, err := engine.CorrelateUser(context.Background(), authIDP, testUser)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if results[0].LinkState != LinkStateLinkedAuto {
		t.Errorf("expected %q, got %q", LinkStateLinkedAuto, results[0].LinkState)
	}
	// Must have used the target IDP's mapping attribute, not the fallback.
	if capturedAttr != "userPrincipalName" {
		t.Errorf("expected search attr 'userPrincipalName' from target mapping, got %q", capturedAttr)
	}
}

// TestResolveCanonicalAttribute_ListMappingsError covers engine.go:437-439 —
// ListAttributeMappings error in ResolveCanonicalAttribute.
func TestResolveCanonicalAttribute_ListMappingsError(t *testing.T) {
	store := newMockStore()
	store.listAttrMappingsErrFor[authIDP] = errors.New("db error")

	authProv := &mockProvider{id: authIDP, provType: idp.ProviderTypeAD}
	engine := setupEngine(store, authProv)

	_, err := engine.ResolveCanonicalAttribute(context.Background(), authIDP, testUser, "email")
	if err == nil {
		t.Fatal("expected error when ListAttributeMappings fails")
	}
}

// TestResolveCanonicalAttribute_ProviderNotInRegistry covers engine.go:460-462
// — auth provider is not registered in the registry.
func TestResolveCanonicalAttribute_ProviderNotInRegistry(t *testing.T) {
	store := newMockStore()
	store.attrMappings[authIDP] = defaultAttrMappings()
	// No providers registered.
	engine := setupEngine(store)

	_, err := engine.ResolveCanonicalAttribute(context.Background(), authIDP, testUser, "email")
	if err == nil {
		t.Fatal("expected error when auth provider not in registry")
	}
}

// TestResolveCanonicalAttribute_ViaSelfMapping covers engine.go:468-475 —
// the self-mapping exists and is used to resolve the user DN.
func TestResolveCanonicalAttribute_ViaSelfMapping(t *testing.T) {
	store := newMockStore()
	store.attrMappings[authIDP] = defaultAttrMappings()
	// Pre-populate a self-mapping for (authIDP, testUser, authIDP).
	store.mappings[mappingKey(authIDP, testUser, authIDP)] = &db.UserIDPMapping{
		ID:              10,
		AuthProviderID:  authIDP,
		AuthUsername:    testUser,
		TargetIDPID:     authIDP,
		TargetAccountDN: targetDN,
		LinkType:        "auto",
	}

	authProv := &mockProvider{
		id:       authIDP,
		provType: idp.ProviderTypeAD,
		getAttrFunc: func(_ context.Context, userDN, attr string) (string, error) {
			if userDN == targetDN && attr == "mail" {
				return "jdoe@example.com", nil
			}
			return "", errors.New("unexpected call")
		},
	}
	engine := setupEngine(store, authProv)

	val, err := engine.ResolveCanonicalAttribute(context.Background(), authIDP, testUser, "email")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != "jdoe@example.com" {
		t.Errorf("expected 'jdoe@example.com', got %q", val)
	}
}

// TestResolveCanonicalAttribute_ViaSAMAccountName covers engine.go:481-483 —
// uid search fails but sAMAccountName search succeeds.
func TestResolveCanonicalAttribute_ViaSAMAccountName(t *testing.T) {
	const samDN = "CN=jdoe,OU=Users,DC=example,DC=com"

	store := newMockStore()
	store.attrMappings[authIDP] = defaultAttrMappings()
	// No self-mapping.

	authProv := &mockProvider{
		id:       authIDP,
		provType: idp.ProviderTypeAD,
		searchFunc: func(_ context.Context, attr, value string) (string, error) {
			if attr == "sAMAccountName" && value == testUser {
				return samDN, nil
			}
			return "", idp.ErrNotFound // uid search fails
		},
		getAttrFunc: func(_ context.Context, userDN, attr string) (string, error) {
			if userDN == samDN && attr == "mail" {
				return "jdoe@example.com", nil
			}
			return "", errors.New("unexpected call")
		},
	}
	engine := setupEngine(store, authProv)

	val, err := engine.ResolveCanonicalAttribute(context.Background(), authIDP, testUser, "email")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != "jdoe@example.com" {
		t.Errorf("expected 'jdoe@example.com', got %q", val)
	}
}

// TestResolveCanonicalAttribute_GetUserAttrFails covers engine.go:499-501 —
// GetUserAttribute returns an error.
func TestResolveCanonicalAttribute_GetUserAttrFails(t *testing.T) {
	store := newMockStore()
	store.attrMappings[authIDP] = defaultAttrMappings()
	// No self-mapping.

	authProv := &mockProvider{
		id:       authIDP,
		provType: idp.ProviderTypeAD,
		getAttrFunc: func(_ context.Context, _, _ string) (string, error) {
			return "", errors.New("LDAP attribute read failed")
		},
	}
	engine := setupEngine(store, authProv)

	_, err := engine.ResolveCanonicalAttribute(context.Background(), authIDP, testUser, "email")
	if err == nil {
		t.Fatal("expected error when GetUserAttribute fails")
	}
}

// TestVerifyAutoMapping_RuleGone_DowngradeFails covers engine.go:218-220 —
// GetCorrelationRule returns ErrNotFound and DowngradeMapping itself fails.
func TestVerifyAutoMapping_RuleGone_DowngradeFails(t *testing.T) {
	store := newMockStore()
	store.enabledIDPs = defaultEnabledIDPs()
	// No correlationRule for targetIDP → GetCorrelationRule returns ErrNotFound.
	store.downgradeMappingErr = errors.New("downgrade failed: db locked")

	now := time.Now().UTC()
	store.mappings[mappingKey(authIDP, testUser, targetIDP)] = &db.UserIDPMapping{
		ID:              91,
		AuthProviderID:  authIDP,
		AuthUsername:    testUser,
		TargetIDPID:     targetIDP,
		TargetAccountDN: targetDN,
		LinkType:        "auto",
		LinkedAt:        now.Add(-24 * time.Hour),
		VerifiedAt:      &now,
	}

	authProv := &mockProvider{id: authIDP, provType: idp.ProviderTypeAD}
	targetProv := &mockProvider{id: targetIDP, provType: idp.ProviderTypeAD}
	engine := setupEngine(store, authProv, targetProv)

	results, err := engine.CorrelateUser(context.Background(), authIDP, testUser)
	if err != nil {
		t.Fatalf("unexpected top-level error: %v", err)
	}
	// Engine absorbs the error and produces an unlinked result.
	if results[0].LinkState != LinkStateUnlinked {
		t.Errorf("expected %q when downgrade fails, got %q", LinkStateUnlinked, results[0].LinkState)
	}
}

// TestVerifyAutoMapping_CanonicalResolveFails_DowngradeFails covers engine.go:230-232 —
// ResolveCanonicalAttribute fails and DowngradeMapping itself fails.
func TestVerifyAutoMapping_CanonicalResolveFails_DowngradeFails(t *testing.T) {
	store := newMockStore()
	store.enabledIDPs = defaultEnabledIDPs()
	store.correlationRule[targetIDP] = defaultRule()
	// No attrMappings for authIDP → ResolveCanonicalAttribute returns error.
	store.downgradeMappingErr = errors.New("downgrade failed")

	now := time.Now().UTC()
	store.mappings[mappingKey(authIDP, testUser, targetIDP)] = &db.UserIDPMapping{
		ID:              92,
		AuthProviderID:  authIDP,
		AuthUsername:    testUser,
		TargetIDPID:     targetIDP,
		TargetAccountDN: targetDN,
		LinkType:        "auto",
		LinkedAt:        now.Add(-24 * time.Hour),
		VerifiedAt:      &now,
	}

	authProv := &mockProvider{id: authIDP, provType: idp.ProviderTypeAD}
	targetProv := &mockProvider{id: targetIDP, provType: idp.ProviderTypeAD}
	engine := setupEngine(store, authProv, targetProv)

	results, err := engine.CorrelateUser(context.Background(), authIDP, testUser)
	if err != nil {
		t.Fatalf("unexpected top-level error: %v", err)
	}
	if results[0].LinkState != LinkStateUnlinked {
		t.Errorf("expected %q when downgrade fails, got %q", LinkStateUnlinked, results[0].LinkState)
	}
}

// TestVerifyAutoMapping_SearchFails_DowngradeFails covers engine.go:247-249 —
// provider.SearchUser fails and DowngradeMapping itself fails.
func TestVerifyAutoMapping_SearchFails_DowngradeFails(t *testing.T) {
	store := newMockStore()
	store.enabledIDPs = defaultEnabledIDPs()
	store.correlationRule[targetIDP] = defaultRule()
	store.attrMappings[authIDP] = defaultAttrMappings()
	store.downgradeMappingErr = errors.New("downgrade failed")

	now := time.Now().UTC()
	store.mappings[mappingKey(authIDP, testUser, targetIDP)] = &db.UserIDPMapping{
		ID:              93,
		AuthProviderID:  authIDP,
		AuthUsername:    testUser,
		TargetIDPID:     targetIDP,
		TargetAccountDN: targetDN,
		LinkType:        "auto",
		LinkedAt:        now.Add(-24 * time.Hour),
		VerifiedAt:      &now,
	}

	authProv := &mockProvider{
		id:       authIDP,
		provType: idp.ProviderTypeAD,
		getAttrFunc: func(_ context.Context, _, _ string) (string, error) {
			return "jdoe@example.com", nil
		},
	}
	targetProv := &mockProvider{
		id:       targetIDP,
		provType: idp.ProviderTypeAD,
		searchFunc: func(_ context.Context, _, _ string) (string, error) {
			return "", errors.New("LDAP search failed")
		},
	}
	engine := setupEngine(store, authProv, targetProv)

	results, err := engine.CorrelateUser(context.Background(), authIDP, testUser)
	if err != nil {
		t.Fatalf("unexpected top-level error: %v", err)
	}
	if results[0].LinkState != LinkStateUnlinked {
		t.Errorf("expected %q when downgrade fails, got %q", LinkStateUnlinked, results[0].LinkState)
	}
}

// TestAttemptAutoCorrelation_DeleteWarningError covers engine.go:410-412 — the
// DeleteCorrelationWarning failure path during successful auto-correlation.
// The warning is logged but the result is still LinkStateLinkedAuto.
func TestAttemptAutoCorrelation_DeleteWarningError(t *testing.T) {
	store := newMockStore()
	store.enabledIDPs = defaultEnabledIDPs()
	store.correlationRule[targetIDP] = defaultRule()
	store.attrMappings[authIDP] = defaultAttrMappings()
	store.deleteCorrelationWarnErr = errors.New("warn delete failed")

	authProv := &mockProvider{
		id:       authIDP,
		provType: idp.ProviderTypeAD,
		getAttrFunc: func(_ context.Context, _, _ string) (string, error) {
			return "jdoe@example.com", nil
		},
	}
	targetProv := &mockProvider{
		id:       targetIDP,
		provType: idp.ProviderTypeAD,
		searchFunc: func(_ context.Context, _, _ string) (string, error) {
			return targetDN, nil
		},
	}
	engine := setupEngine(store, authProv, targetProv)

	results, err := engine.CorrelateUser(context.Background(), authIDP, testUser)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Despite the DeleteCorrelationWarning failure the mapping is created.
	if results[0].LinkState != LinkStateLinkedAuto {
		t.Errorf("expected %q even when DeleteCorrelationWarning fails, got %q", LinkStateLinkedAuto, results[0].LinkState)
	}
}
