package handler

import (
	"sort"

	"github.com/hanej/passport/internal/db"
)

// localAdminName is the label shown on the built-in Local Admin card.
const localAdminName = "Local Admin"

// localAdminRecord builds the pseudo-provider for the built-in Local Admin
// account, so it can be grouped and ordered like a real provider despite having
// no identity_providers row.
func localAdminRecord(p db.LocalAdminPlacement) db.IdentityProviderRecord {
	return db.IdentityProviderRecord{
		ID:           db.LocalAdminIDPID,
		FriendlyName: localAdminName,
		ProviderType: db.LocalAdminIDPID,
		Enabled:      true,
		GroupID:      p.GroupID,
		DisplayOrder: p.DisplayOrder,
	}
}

// withLocalAdmin merges the Local Admin pseudo-provider into idps. The store
// returns providers already ordered by display_order, so a stable sort drops
// Local Admin into its arranged position without disturbing the rest.
func withLocalAdmin(idps []db.IdentityProviderRecord, p db.LocalAdminPlacement) []db.IdentityProviderRecord {
	merged := make([]db.IdentityProviderRecord, 0, len(idps)+1)
	merged = append(merged, idps...)
	merged = append(merged, localAdminRecord(p))
	sort.SliceStable(merged, func(i, j int) bool {
		return merged[i].DisplayOrder < merged[j].DisplayOrder
	})
	return merged
}

// IDPSection is one group of providers as arranged for display. Group is nil
// for the trailing section holding providers that have not been assigned.
type IDPSection struct {
	Group *db.IDPGroup
	IDPs  []db.IdentityProviderRecord
}

// sectionIDPs arranges providers into their groups in group display order,
// followed by any ungrouped providers. Providers keep the order they arrive in,
// which the store has already sorted by display_order.
//
// Groups with no providers are omitted, so an empty group never renders a
// heading. Providers referencing a group that no longer exists fall back to the
// ungrouped section rather than disappearing.
func sectionIDPs(groups []db.IDPGroup, idps []db.IdentityProviderRecord) []IDPSection {
	known := make(map[int64]bool, len(groups))
	for _, g := range groups {
		known[g.ID] = true
	}

	byGroup := make(map[int64][]db.IdentityProviderRecord, len(groups))
	var ungrouped []db.IdentityProviderRecord
	for _, rec := range idps {
		if rec.GroupID != nil && known[*rec.GroupID] {
			byGroup[*rec.GroupID] = append(byGroup[*rec.GroupID], rec)
			continue
		}
		ungrouped = append(ungrouped, rec)
	}

	sections := make([]IDPSection, 0, len(groups)+1)
	for i := range groups {
		members := byGroup[groups[i].ID]
		if len(members) == 0 {
			continue
		}
		sections = append(sections, IDPSection{Group: &groups[i], IDPs: members})
	}
	if len(ungrouped) > 0 {
		sections = append(sections, IDPSection{IDPs: ungrouped})
	}
	return sections
}
