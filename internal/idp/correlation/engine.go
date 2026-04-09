// Package correlation implements the account correlation engine that runs at
// login time to match user accounts across identity providers.
package correlation

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/hanej/passport/internal/db"
	"github.com/hanej/passport/internal/idp"
)

// Link states reported in MappingResult.
const (
	LinkStateLinkedAuto   = "linked_auto"
	LinkStateLinkedManual = "linked_manual"
	LinkStateUnlinked     = "unlinked"
)

// CorrelationStore defines the database methods the correlation engine needs.
type CorrelationStore interface {
	ListEnabledIDPs(ctx context.Context) ([]db.IdentityProviderRecord, error)
	ListAttributeMappings(ctx context.Context, idpID string) ([]db.AttributeMapping, error)
	GetCorrelationRule(ctx context.Context, idpID string) (*db.CorrelationRule, error)
	GetMapping(ctx context.Context, authProviderID, authUsername, targetIDPID string) (*db.UserIDPMapping, error)
	HasMappingToTarget(ctx context.Context, authUsername, targetIDPID string) (bool, error)
	UpsertMapping(ctx context.Context, m *db.UserIDPMapping) error
	UpdateMappingVerified(ctx context.Context, id int64, verifiedAt time.Time) error
	DowngradeMapping(ctx context.Context, id int64) error
	SetCorrelationWarning(ctx context.Context, w *db.CorrelationWarning) error
	DeleteCorrelationWarning(ctx context.Context, authUsername, targetIDPID string) error
}

// MappingResult describes the correlation outcome for a single target IDP.
type MappingResult struct {
	IDPID            string
	IDPFriendlyName  string
	IDPType          string
	LinkState        string
	TargetAccountDN  string
	AmbiguityWarning bool
}

// Engine correlates a user who authenticated against one IDP with their
// accounts on all other enabled IDPs.
type Engine struct {
	store    CorrelationStore
	registry *idp.Registry
	logger   *slog.Logger
}

// New creates a new correlation engine.
func New(store CorrelationStore, registry *idp.Registry, logger *slog.Logger) *Engine {
	return &Engine{
		store:    store,
		registry: registry,
		logger:   logger,
	}
}

// CorrelateUser runs the correlation logic for the given authenticated user
// against every enabled target IDP. It returns one MappingResult per target
// IDP. Errors from individual IDPs are logged but do not abort the overall
// process — the affected IDP is reported as unlinked.
func (e *Engine) CorrelateUser(ctx context.Context, authProviderID, authUsername string) ([]MappingResult, error) {
	e.logger.Debug("starting correlation",
		"auth_provider", authProviderID,
		"auth_user", authUsername,
	)

	enabledIDPs, err := e.store.ListEnabledIDPs(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing enabled IDPs: %w", err)
	}

	e.logger.Debug("correlation: enabled IDPs loaded", "count", len(enabledIDPs))

	var results []MappingResult

	for _, target := range enabledIDPs {
		result := MappingResult{
			IDPID:           target.ID,
			IDPFriendlyName: target.FriendlyName,
			IDPType:         target.ProviderType,
			LinkState:       LinkStateUnlinked,
		}

		e.logger.Debug("correlating for target IDP",
			"target_idp", target.ID,
			"auth_provider", authProviderID,
			"auth_user", authUsername,
		)

		mr, err := e.correlateForTarget(ctx, authProviderID, authUsername, target)
		if err != nil {
			e.logger.Warn("correlation failed for target IDP",
				"target_idp", target.ID,
				"auth_provider", authProviderID,
				"auth_user", authUsername,
				"error", err,
			)
			// Keep the default unlinked result.
			results = append(results, result)
			continue
		}

		e.logger.Debug("correlation result",
			"target_idp", target.ID,
			"link_state", mr.LinkState,
			"target_dn", mr.TargetAccountDN,
		)

		results = append(results, *mr)
	}

	return results, nil
}

// correlateForTarget handles the correlation logic for a single target IDP.
func (e *Engine) correlateForTarget(ctx context.Context, authProviderID, authUsername string, target db.IdentityProviderRecord) (*MappingResult, error) {
	result := &MappingResult{
		IDPID:           target.ID,
		IDPFriendlyName: target.FriendlyName,
		IDPType:         target.ProviderType,
		LinkState:       LinkStateUnlinked,
	}

	// Step 1: Check for an existing mapping.
	existing, err := e.store.GetMapping(ctx, authProviderID, authUsername, target.ID)
	if err != nil && !errors.Is(err, db.ErrNotFound) {
		return nil, fmt.Errorf("fetching mapping: %w", err)
	}

	if existing != nil {
		return e.verifyExistingMapping(ctx, existing, target, result)
	}

	// No existing mapping — attempt auto-correlation.
	return e.attemptAutoCorrelation(ctx, authProviderID, authUsername, target, result)
}

// verifyExistingMapping re-verifies a previously created mapping.
func (e *Engine) verifyExistingMapping(ctx context.Context, m *db.UserIDPMapping, target db.IdentityProviderRecord, result *MappingResult) (*MappingResult, error) {
	provider, ok := e.registry.Get(target.ID)
	if !ok {
		return nil, fmt.Errorf("provider %q not in registry", target.ID)
	}

	switch m.LinkType {
	case "manual":
		return e.verifyManualMapping(ctx, m, provider, result)
	case "auto":
		return e.verifyAutoMapping(ctx, m, target, provider, result)
	default:
		return nil, fmt.Errorf("unknown link type %q", m.LinkType)
	}
}

// verifyManualMapping checks that the manually-linked DN still exists in the
// target directory.
func (e *Engine) verifyManualMapping(ctx context.Context, m *db.UserIDPMapping, provider idp.Provider, result *MappingResult) (*MappingResult, error) {
	// Search for the stored DN by looking it up via a distinguishedName search.
	_, err := provider.SearchUser(ctx, "distinguishedName", m.TargetAccountDN)
	if err == nil {
		// Still valid — update verified_at.
		now := time.Now().UTC()
		if updateErr := e.store.UpdateMappingVerified(ctx, m.ID, now); updateErr != nil {
			e.logger.Warn("failed to update verified_at", "mapping_id", m.ID, "error", updateErr)
		}
		result.LinkState = LinkStateLinkedManual
		result.TargetAccountDN = m.TargetAccountDN
		return result, nil
	}

	// DN no longer found — downgrade.
	e.logger.Info("manual mapping verification failed, downgrading",
		"mapping_id", m.ID,
		"target_dn", m.TargetAccountDN,
		"error", err,
	)
	if downErr := e.store.DowngradeMapping(ctx, m.ID); downErr != nil {
		return nil, fmt.Errorf("downgrading manual mapping: %w", downErr)
	}
	result.LinkState = LinkStateUnlinked
	return result, nil
}

// verifyAutoMapping re-runs the correlation rule to confirm the auto mapping
// is still valid.
func (e *Engine) verifyAutoMapping(ctx context.Context, m *db.UserIDPMapping, target db.IdentityProviderRecord, provider idp.Provider, result *MappingResult) (*MappingResult, error) {
	// Self-mappings (auth provider == target) are created at login and don't
	// require a correlation rule. Keep them as-is.
	if m.AuthProviderID == m.TargetIDPID {
		now := time.Now().UTC()
		if updateErr := e.store.UpdateMappingVerified(ctx, m.ID, now); updateErr != nil {
			e.logger.Warn("failed to update verified_at for self-mapping", "mapping_id", m.ID, "error", updateErr)
		}
		result.LinkState = LinkStateLinkedAuto
		result.TargetAccountDN = m.TargetAccountDN
		e.logger.Debug("self-mapping verified",
			"mapping_id", m.ID,
			"target_dn", m.TargetAccountDN,
		)
		return result, nil
	}

	rule, err := e.store.GetCorrelationRule(ctx, target.ID)
	if err != nil {
		// Rule deleted since mapping was created — downgrade.
		if errors.Is(err, db.ErrNotFound) {
			e.logger.Debug("no correlation rule found, downgrading auto mapping",
				"mapping_id", m.ID,
				"target_idp", target.ID,
			)
			if downErr := e.store.DowngradeMapping(ctx, m.ID); downErr != nil {
				return nil, fmt.Errorf("downgrading auto mapping (rule gone): %w", downErr)
			}
			return result, nil
		}
		return nil, fmt.Errorf("fetching correlation rule: %w", err)
	}

	// Resolve the canonical attribute value from the authenticating IDP.
	canonicalValue, err := e.ResolveCanonicalAttribute(ctx, m.AuthProviderID, m.AuthUsername, rule.SourceCanonicalAttr)
	if err != nil {
		// Cannot resolve — downgrade.
		if downErr := e.store.DowngradeMapping(ctx, m.ID); downErr != nil {
			return nil, fmt.Errorf("downgrading auto mapping (resolve failed): %w", downErr)
		}
		return result, nil
	}

	targetDirAttr, err := e.resolveTargetDirectoryAttr(ctx, target.ID, rule)
	if err != nil {
		if downErr := e.store.DowngradeMapping(ctx, m.ID); downErr != nil {
			return nil, fmt.Errorf("downgrading auto mapping (target attr resolve failed): %w", downErr)
		}
		return result, nil
	}

	dn, err := provider.SearchUser(ctx, targetDirAttr, canonicalValue)
	if err != nil {
		// No match or multiple — downgrade.
		if downErr := e.store.DowngradeMapping(ctx, m.ID); downErr != nil {
			return nil, fmt.Errorf("downgrading auto mapping (search failed): %w", downErr)
		}
		if errors.Is(err, idp.ErrMultipleMatches) {
			result.AmbiguityWarning = true
			if warnErr := e.store.SetCorrelationWarning(ctx, &db.CorrelationWarning{
				AuthUsername: m.AuthUsername,
				TargetIDPID:  target.ID,
				WarningType:  "ambiguous_match",
				Message:      fmt.Sprintf("Multiple accounts in %s now match your credentials. Please re-link your account manually.", target.FriendlyName),
			}); warnErr != nil {
				e.logger.Warn("failed to persist ambiguity warning", "error", warnErr)
			}
		}
		return result, nil
	}

	// Match found — re-verify. Ensure it is the same DN.
	if dn != m.TargetAccountDN {
		// DN changed — downgrade old, could re-link but safer to let next pass handle it.
		if downErr := e.store.DowngradeMapping(ctx, m.ID); downErr != nil {
			return nil, fmt.Errorf("downgrading auto mapping (dn changed): %w", downErr)
		}
		return result, nil
	}

	now := time.Now().UTC()
	if updateErr := e.store.UpdateMappingVerified(ctx, m.ID, now); updateErr != nil {
		e.logger.Warn("failed to update verified_at", "mapping_id", m.ID, "error", updateErr)
	}
	result.LinkState = LinkStateLinkedAuto
	result.TargetAccountDN = dn
	return result, nil
}

// attemptAutoCorrelation tries to create an automatic mapping using the
// correlation rule configured for the target IDP.
func (e *Engine) attemptAutoCorrelation(ctx context.Context, authProviderID, authUsername string, target db.IdentityProviderRecord, result *MappingResult) (*MappingResult, error) {
	// Step 4: Load the correlation rule.
	rule, err := e.store.GetCorrelationRule(ctx, target.ID)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			e.logger.Debug("no correlation rule for target IDP, skipping",
				"target_idp", target.ID,
				"auth_provider", authProviderID,
			)
			return result, nil
		}
		return nil, fmt.Errorf("fetching correlation rule: %w", err)
	}

	e.logger.Debug("correlation rule loaded",
		"target_idp", target.ID,
		"source_attr", rule.SourceCanonicalAttr,
		"match_mode", rule.MatchMode,
	)

	// Step 5: Resolve the canonical attribute value from the auth provider.
	canonicalValue, err := e.ResolveCanonicalAttribute(ctx, authProviderID, authUsername, rule.SourceCanonicalAttr)
	if err != nil {
		e.logger.Debug("failed to resolve canonical attribute",
			"target_idp", target.ID,
			"canonical_attr", rule.SourceCanonicalAttr,
			"error", err,
		)
		return nil, fmt.Errorf("resolving canonical attribute %q: %w", rule.SourceCanonicalAttr, err)
	}

	e.logger.Debug("canonical attribute resolved",
		"target_idp", target.ID,
		"canonical_attr", rule.SourceCanonicalAttr,
		"value", canonicalValue,
	)

	// Step 6: Resolve the target directory attribute from the target IDP's
	// attribute mappings using the same canonical name. Fall back to the
	// explicitly stored TargetDirectoryAttr if set.
	targetDirAttr, err := e.resolveTargetDirectoryAttr(ctx, target.ID, rule)
	if err != nil {
		e.logger.Debug("failed to resolve target directory attribute",
			"target_idp", target.ID,
			"canonical_attr", rule.SourceCanonicalAttr,
			"error", err,
		)
		return nil, fmt.Errorf("resolving target directory attr for %q: %w", target.ID, err)
	}

	e.logger.Debug("target directory attribute resolved",
		"target_idp", target.ID,
		"target_dir_attr", targetDirAttr,
	)

	// Step 7: Search the target IDP.
	provider, ok := e.registry.Get(target.ID)
	if !ok {
		return nil, fmt.Errorf("provider %q not in registry", target.ID)
	}

	dn, err := provider.SearchUser(ctx, targetDirAttr, canonicalValue)
	if err != nil {
		if errors.Is(err, idp.ErrNotFound) {
			e.logger.Debug("auto-correlation: no match in target directory",
				"target_idp", target.ID,
				"search_attr", rule.TargetDirectoryAttr,
				"search_value", canonicalValue,
			)
			return result, nil
		}
		if errors.Is(err, idp.ErrMultipleMatches) {
			e.logger.Warn("auto-correlation: multiple matches in target directory",
				"target_idp", target.ID,
				"search_attr", rule.TargetDirectoryAttr,
				"search_value", canonicalValue,
			)
			result.AmbiguityWarning = true
			if warnErr := e.store.SetCorrelationWarning(ctx, &db.CorrelationWarning{
				AuthUsername: authUsername,
				TargetIDPID:  target.ID,
				WarningType:  "ambiguous_match",
				Message:      fmt.Sprintf("Multiple accounts in %s match your %s. Please link your account manually.", target.FriendlyName, rule.SourceCanonicalAttr),
			}); warnErr != nil {
				e.logger.Warn("failed to persist ambiguity warning", "error", warnErr)
			}
			return result, nil
		}
		return nil, fmt.Errorf("searching target IDP %q: %w", target.ID, err)
	}

	// Skip if a mapping to this target already exists from any auth provider.
	exists, _ := e.store.HasMappingToTarget(ctx, authUsername, target.ID)
	if exists {
		e.logger.Debug("auto-correlation: mapping to target already exists, skipping",
			"target_idp", target.ID,
			"auth_user", authUsername,
		)
		result.LinkState = LinkStateLinkedAuto
		result.TargetAccountDN = dn
		return result, nil
	}

	e.logger.Info("auto-correlation: match found, creating mapping",
		"target_idp", target.ID,
		"target_dn", dn,
		"auth_provider", authProviderID,
		"auth_user", authUsername,
	)

	// Step 7: Single match — create auto mapping.
	now := time.Now().UTC()
	mapping := &db.UserIDPMapping{
		AuthProviderID:  authProviderID,
		AuthUsername:    authUsername,
		TargetIDPID:     target.ID,
		TargetAccountDN: dn,
		LinkType:        "auto",
		LinkedAt:        now,
		VerifiedAt:      &now,
	}
	if err := e.store.UpsertMapping(ctx, mapping); err != nil {
		return nil, fmt.Errorf("upserting auto mapping: %w", err)
	}

	// Clear any prior ambiguity warning for this user+target now that we have a link.
	if warnErr := e.store.DeleteCorrelationWarning(ctx, authUsername, target.ID); warnErr != nil {
		e.logger.Warn("failed to clear correlation warning", "error", warnErr)
	}

	result.LinkState = LinkStateLinkedAuto
	result.TargetAccountDN = dn
	return result, nil
}

// resolveTargetDirectoryAttr determines which directory attribute to search
// on the target IDP. It first looks up the target IDP's attribute mappings
// for the same canonical name used in the correlation rule. If found, it uses
// that directory attribute. Otherwise, it falls back to the explicitly stored
// TargetDirectoryAttr in the rule (for backward compatibility).
func (e *Engine) resolveTargetDirectoryAttr(ctx context.Context, targetIDPID string, rule *db.CorrelationRule) (string, error) {
	// Look up the target IDP's attribute mappings for the canonical name.
	mappings, err := e.store.ListAttributeMappings(ctx, targetIDPID)
	if err != nil {
		return "", fmt.Errorf("listing attribute mappings for target %q: %w", targetIDPID, err)
	}

	for _, m := range mappings {
		if m.CanonicalName == rule.SourceCanonicalAttr {
			e.logger.Debug("resolved target directory attr from mappings",
				"target_idp", targetIDPID,
				"canonical_name", rule.SourceCanonicalAttr,
				"directory_attr", m.DirectoryAttr,
			)
			return m.DirectoryAttr, nil
		}
	}

	// Fall back to the explicitly stored value.
	if rule.TargetDirectoryAttr != "" {
		e.logger.Debug("using explicit target directory attr from rule",
			"target_idp", targetIDPID,
			"target_dir_attr", rule.TargetDirectoryAttr,
		)
		return rule.TargetDirectoryAttr, nil
	}

	return "", fmt.Errorf("no attribute mapping for canonical %q on target IDP %q and no explicit target attr", rule.SourceCanonicalAttr, targetIDPID)
}

// ResolveCanonicalAttribute looks up the attribute mapping for the
// authenticating IDP to find which directory attribute maps to the given
// canonical name, then calls GetUserAttribute on the IDP provider to
// retrieve the actual value.
func (e *Engine) ResolveCanonicalAttribute(ctx context.Context, authProviderID, authUsername, canonicalName string) (string, error) {
	mappings, err := e.store.ListAttributeMappings(ctx, authProviderID)
	if err != nil {
		return "", fmt.Errorf("listing attribute mappings for %q: %w", authProviderID, err)
	}

	e.logger.Debug("resolving canonical attribute",
		"auth_provider", authProviderID,
		"auth_user", authUsername,
		"canonical_name", canonicalName,
		"mapping_count", len(mappings),
	)

	var dirAttr string
	for _, m := range mappings {
		if m.CanonicalName == canonicalName {
			dirAttr = m.DirectoryAttr
			break
		}
	}
	if dirAttr == "" {
		return "", fmt.Errorf("no attribute mapping for canonical name %q on IDP %q", canonicalName, authProviderID)
	}

	provider, ok := e.registry.Get(authProviderID)
	if !ok {
		return "", fmt.Errorf("auth provider %q not in registry", authProviderID)
	}

	// Resolve the username to a DN first. Try the self-mapping (created at
	// login), then fall back to a directory search.
	userDN := authUsername
	selfMapping, err := e.store.GetMapping(ctx, authProviderID, authUsername, authProviderID)
	if err == nil && selfMapping != nil {
		userDN = selfMapping.TargetAccountDN
		e.logger.Debug("resolved user DN from self-mapping",
			"auth_provider", authProviderID,
			"auth_user", authUsername,
			"user_dn", userDN,
		)
	} else {
		// No self-mapping — search the directory. Try uid then sAMAccountName.
		dn, searchErr := provider.SearchUser(ctx, "uid", authUsername)
		if searchErr != nil {
			dn, searchErr = provider.SearchUser(ctx, "sAMAccountName", authUsername)
		}
		if searchErr == nil {
			userDN = dn
		}
		e.logger.Debug("resolved user DN from directory search",
			"auth_provider", authProviderID,
			"auth_user", authUsername,
			"user_dn", userDN,
			"search_err", searchErr,
		)
	}

	e.logger.Debug("fetching user attribute from directory",
		"auth_provider", authProviderID,
		"user_dn", userDN,
		"directory_attr", dirAttr,
	)

	value, err := provider.GetUserAttribute(ctx, userDN, dirAttr)
	if err != nil {
		return "", fmt.Errorf("reading attribute %q for user %q: %w", dirAttr, userDN, err)
	}

	e.logger.Debug("canonical attribute resolved",
		"canonical_name", canonicalName,
		"directory_attr", dirAttr,
		"value", value,
	)
	return value, nil
}
