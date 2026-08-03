package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hanej/passport/internal/db"
)

func idpRec(id string, groupID *int64) db.IdentityProviderRecord {
	return db.IdentityProviderRecord{ID: id, FriendlyName: id, ProviderType: "ad", GroupID: groupID}
}

func groupIDPtr(id int64) *int64 { return &id }

func sectionSummary(sections []IDPSection) []string {
	var out []string
	for _, sec := range sections {
		name := "(ungrouped)"
		if sec.Group != nil {
			name = sec.Group.Name
		}
		for _, rec := range sec.IDPs {
			name += ":" + rec.ID
		}
		out = append(out, name)
	}
	return out
}

func TestSectionIDPs(t *testing.T) {
	groups := []db.IDPGroup{
		{ID: 1, Name: "Corporate"},
		{ID: 2, Name: "Partners"},
	}

	tests := []struct {
		name   string
		groups []db.IDPGroup
		idps   []db.IdentityProviderRecord
		want   []string
	}{
		{
			name:   "no groups leaves everything ungrouped",
			groups: nil,
			idps:   []db.IdentityProviderRecord{idpRec("a", nil), idpRec("b", nil)},
			want:   []string{"(ungrouped):a:b"},
		},
		{
			name:   "groups come first in display order, ungrouped last",
			groups: groups,
			idps: []db.IdentityProviderRecord{
				idpRec("loose", nil),
				idpRec("corp", groupIDPtr(1)),
				idpRec("partner", groupIDPtr(2)),
			},
			want: []string{"Corporate:corp", "Partners:partner", "(ungrouped):loose"},
		},
		{
			name:   "empty groups are omitted",
			groups: groups,
			idps:   []db.IdentityProviderRecord{idpRec("corp", groupIDPtr(1))},
			want:   []string{"Corporate:corp"},
		},
		{
			name:   "providers referencing a deleted group fall back to ungrouped",
			groups: groups,
			idps:   []db.IdentityProviderRecord{idpRec("orphan", groupIDPtr(99))},
			want:   []string{"(ungrouped):orphan"},
		},
		{
			name:   "provider order within a group is preserved",
			groups: groups,
			idps: []db.IdentityProviderRecord{
				idpRec("second", groupIDPtr(1)),
				idpRec("first", groupIDPtr(1)),
			},
			want: []string{"Corporate:second:first"},
		},
		{
			name:   "no providers produces no sections",
			groups: groups,
			idps:   nil,
			want:   nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := sectionSummary(sectionIDPs(tc.groups, tc.idps))
			if len(got) != len(tc.want) {
				t.Fatalf("expected %v, got %v", tc.want, got)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Fatalf("expected %v, got %v", tc.want, got)
				}
			}
		})
	}
}

// TestSectionIDPs_GroupPointersAreDistinct guards against the classic
// range-variable aliasing bug, which would make every section render the last
// group's name.
func TestSectionIDPs_GroupPointersAreDistinct(t *testing.T) {
	groups := []db.IDPGroup{{ID: 1, Name: "Corporate"}, {ID: 2, Name: "Partners"}}
	idps := []db.IdentityProviderRecord{idpRec("a", groupIDPtr(1)), idpRec("b", groupIDPtr(2))}

	sections := sectionIDPs(groups, idps)
	if len(sections) != 2 {
		t.Fatalf("expected 2 sections, got %d", len(sections))
	}
	if sections[0].Group.Name == sections[1].Group.Name {
		t.Fatalf("sections share a group pointer: both are %q", sections[0].Group.Name)
	}
}

// TestGroupedPages_RenderWithRealTemplates exercises the group markup in the
// shipped templates, which the stub renderers used elsewhere cannot catch.
func TestGroupedPages_RenderWithRealTemplates(t *testing.T) {
	logger := testLogger()
	r, err := NewRenderer("", logger)
	if err != nil {
		t.Fatalf("NewRenderer: %v", err)
	}

	collapsible := &db.IDPGroup{ID: 1, Name: "Corporate", Description: "HQ **directories**", Icon: "bi-building", Collapsible: true, StartCollapsed: true}
	plain := &db.IDPGroup{ID: 2, Name: "Partners"}

	tests := []struct {
		name     string
		page     string
		data     PageData
		contains []string
	}{
		{
			name: "login page",
			page: "login.html",
			data: PageData{Title: "Login", Data: map[string]any{"Sections": []LoginIDPSection{
				{Group: collapsible, IDPs: []LoginIDPCard{
					{IdentityProviderRecord: db.IdentityProviderRecord{ID: "corp", FriendlyName: "Corporate AD", ProviderType: "ad"}},
					{IdentityProviderRecord: localAdminRecord(db.LocalAdminPlacement{}), IsLocal: true},
				}},
				{Group: plain, IDPs: []LoginIDPCard{{IdentityProviderRecord: db.IdentityProviderRecord{ID: "portal", FriendlyName: "Partner Portal", ProviderType: "weblink"}, WebLinkURL: "https://portal.example.com"}}},
				{IDPs: []LoginIDPCard{{IdentityProviderRecord: db.IdentityProviderRecord{ID: "loose", FriendlyName: "Other Directory", ProviderType: "freeipa"}}}},
			}}},
			// Local Admin renders from the section data now, so it can sit inside
			// a group rather than always trailing the page.
			contains: []string{"Corporate", "Partners", "Other Directory", `id="idp-group-1"`,
				`href="https://portal.example.com"`, `data-provider-id="local"`, "Built-in administrator account",
				`aria-expanded="false"`},
		},
		{
			name: "dashboard",
			page: "dashboard.html",
			data: PageData{
				Title:   "Dashboard",
				Session: &db.Session{Username: "alice"},
				Data: map[string]any{
					"Sections": []DashboardSection{
						{Group: collapsible, Panels: []IDPPanel{{IDP: db.IdentityProviderRecord{ID: "corp", FriendlyName: "Corporate AD", ProviderType: "ad"}}}},
						{Group: plain, Links: []IDPLink{{IDP: db.IdentityProviderRecord{ID: "portal", FriendlyName: "Partner Portal"}, URL: "https://portal.example.com"}}},
					},
					"ProviderID":  "corp",
					"HasUnlinked": false,
				},
			},
			contains: []string{"Corporate", "Partners", `id="dash-group-1"`, `href="https://portal.example.com"`},
		},
		{
			name: "admin arrangement page",
			page: "admin_idp_groups.html",
			data: PageData{
				Title:   "Provider Groups",
				Session: &db.Session{Username: "admin", IsAdmin: true},
				Data: map[string]any{
					"Sections": []GroupArrangement{
						{Group: collapsible, IDPs: []ArrangementIDP{
							{ID: "corp", FriendlyName: "Corporate AD", ProviderType: "ad", Enabled: true},
							{ID: "local", FriendlyName: "Local Admin", ProviderType: "local", Enabled: true},
						}},
						{Group: plain},
					},
					"Ungrouped":  []ArrangementIDP{{ID: "loose", FriendlyName: "Other Directory", ProviderType: "weblink"}},
					"GroupCount": 2,
					"ActivePage": "idp-groups",
				},
			},
			// The hooks the arrangement JavaScript binds to. A rename here would
			// silently break drag-and-drop, which no other test would catch.
			contains: []string{
				`id="arrangement"`, `data-arrange-url="/admin/idp/groups/arrange"`,
				`id="group-list"`, `id="save-arrangement"`, `id="arrange-hint"`,
				"group-card", "idp-dropzone", `draggable="true"`,
				`data-idp-move="up"`, `data-group-move="down"`,
				`data-group-id="1"`, `data-idp-id="corp"`, `data-idp-id="loose"`,
				`data-idp-id="local"`, "Built-in",
				`data-group-start-collapsed="1"`, `id="group-icon-picker"`, `name="start_collapsed"`,
				"Empty", "Ungrouped",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Render(w, req, tc.page, tc.data)
			if w.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d; body excerpt: %s", w.Code, excerpt(w.Body.String()))
			}
			body := w.Body.String()
			for _, want := range tc.contains {
				if !strings.Contains(body, want) {
					t.Errorf("expected rendered page to contain %q", want)
				}
			}
		})
	}
}
