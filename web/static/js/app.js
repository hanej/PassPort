/* ============================================================
   PassPort Client-Side JavaScript
   Vanilla JS — no framework dependencies
   ============================================================ */

document.addEventListener('DOMContentLoaded', function () {
    initPasswordToggles();
    initPasswordMatchValidation();
    initIDPStatusChecks();
    initTestConnectionButtons();
    initTestConnectionForms();
    initSMTPTest();
    initAttributeMappingRows();
    initFlashAutoDismiss();
    initViewGroupMembers();
    initExpirationFilters();
    initDryRun();
    initRunNow();
    initPasswordPolicyToggles();
    initUnsavedChangesWarning();

    // Initialize Bootstrap tooltips on elements with data-bs-toggle="tooltip".
    document.querySelectorAll('[data-bs-toggle="tooltip"]').forEach(function (el) {
        new bootstrap.Tooltip(el);
    });

    // Initialize Bootstrap popovers on elements with data-bs-toggle="popover".
    document.querySelectorAll('[data-bs-toggle="popover"]').forEach(function (el) {
        new bootstrap.Popover(el);
    });
});

/* ---- Show/Hide Password Toggle ---- */

function initPasswordToggles() {
    document.querySelectorAll('.toggle-password').forEach(function (btn) {
        btn.addEventListener('click', function () {
            var targetId = this.getAttribute('data-target');
            var input = document.getElementById(targetId);
            if (!input) return;

            var icon = this.querySelector('i');
            if (input.type === 'password') {
                input.type = 'text';
                icon.classList.remove('bi-eye');
                icon.classList.add('bi-eye-slash');
            } else {
                input.type = 'password';
                icon.classList.remove('bi-eye-slash');
                icon.classList.add('bi-eye');
            }
        });
    });
}

/* ---- Password Match Validation ---- */

function initPasswordMatchValidation() {
    document.querySelectorAll('.password-change-form').forEach(function (form) {
        var newPw = form.querySelector('.new-password');
        var confirmPw = form.querySelector('.confirm-password');
        var submitBtn = form.querySelector('.pw-submit-btn');

        if (!newPw || !confirmPw || !submitBtn) return;

        // Find the match indicator — look for it within the form or by ID
        var indicator = form.querySelector('.password-match-indicator');

        function validate() {
            var newVal = newPw.value;
            var confirmVal = confirmPw.value;

            if (!confirmVal) {
                if (indicator) {
                    indicator.textContent = '';
                    indicator.className = 'password-match-indicator mt-1';
                }
                submitBtn.disabled = true;
                return;
            }

            if (newVal === confirmVal) {
                if (indicator) {
                    indicator.textContent = ' Passwords match';
                    indicator.className = 'password-match-indicator mt-1 match';
                }
                submitBtn.disabled = false;
            } else {
                if (indicator) {
                    indicator.textContent = ' Passwords do not match';
                    indicator.className = 'password-match-indicator mt-1 no-match';
                }
                submitBtn.disabled = true;
            }
        }

        newPw.addEventListener('input', validate);
        confirmPw.addEventListener('input', validate);

        // Submit on Enter in any password field, but only when the button is enabled.
        form.querySelectorAll('.password-field').forEach(function (field) {
            field.addEventListener('keydown', function (e) {
                if (e.key === 'Enter' && !submitBtn.disabled) {
                    e.preventDefault();
                    form.requestSubmit(submitBtn);
                }
            });
        });
    });
}

/* ---- AJAX IDP Status Check ---- */

function initIDPStatusChecks() {
    var statusElements = document.querySelectorAll('.idp-status');
    if (statusElements.length === 0) return;

    statusElements.forEach(function (el) {
        var idpId = el.getAttribute('data-idp-id');
        if (!idpId) return;

        fetch('/idp-status/' + encodeURIComponent(idpId), {
            method: 'GET',
            headers: { 'Accept': 'application/json' }
        })
        .then(function (response) {
            return response.json();
        })
        .then(function (data) {
            el.innerHTML = '';
            if (data.status === 'online') {
                el.className = 'status-indicator status-online idp-status';
                el.textContent = 'Online';
            } else {
                el.className = 'status-indicator status-offline idp-status';
                el.textContent = 'Offline';
            }
        })
        .catch(function () {
            el.innerHTML = '';
            el.className = 'status-indicator status-offline idp-status';
            el.textContent = 'Unknown';
        });
    });
}

/* ---- AJAX Test Connection (Admin IDP List) ---- */

function initTestConnectionForms() {
    var forms = document.querySelectorAll('.test-connection-form');
    if (forms.length === 0) return;

    forms.forEach(function (form) {
        form.addEventListener('submit', function (e) {
            e.preventDefault();

            var btn = form.querySelector('button[type="submit"]');
            var alertEl = document.getElementById('test-connection-alert');
            var csrf = getCSRFToken();

            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span>';

            fetch(form.action, {
                method: 'POST',
                headers: {
                    'Accept': 'application/json',
                    'X-CSRF-Token': csrf
                }
            })
            .then(function (response) { return response.json(); })
            .then(function (data) {
                alertEl.classList.remove('d-none', 'alert-success', 'alert-danger');
                if (data.status === 'success') {
                    alertEl.classList.add('alert-success');
                    alertEl.innerHTML = '<i class="bi bi-check-circle me-1"></i>' + escapeHtml(data.message || 'Connection successful');
                } else {
                    alertEl.classList.add('alert-danger');
                    alertEl.innerHTML = '<i class="bi bi-x-circle me-1"></i>' + escapeHtml(data.message || 'Connection failed');
                }
            })
            .catch(function () {
                alertEl.classList.remove('d-none', 'alert-success', 'alert-danger');
                alertEl.classList.add('alert-danger');
                alertEl.innerHTML = '<i class="bi bi-x-circle me-1"></i>Request failed';
            })
            .finally(function () {
                btn.disabled = false;
                btn.innerHTML = '<i class="bi bi-plug"></i>';
                setTimeout(function () { alertEl.classList.add('d-none'); }, 5000);
            });
        });
    });
}

/* ---- AJAX Test Connection (Admin IDP Form) ---- */

function initTestConnectionButtons() {
    var testBtn = document.getElementById('test-connection-btn');
    if (!testBtn) return;

    testBtn.addEventListener('click', function () {
        var resultSpan = document.getElementById('test-connection-result');
        var csrf = getCSRFToken();
        var form = testBtn.closest('form') || document.querySelector('form');

        testBtn.disabled = true;
        resultSpan.innerHTML = '<span class="text-muted"><span class="spinner-border spinner-border-sm me-1"></span>Testing...</span>';

        // Serialize form fields as URL-encoded to test unsaved configuration.
        var formData = new URLSearchParams(new FormData(form));

        fetch('/admin/idp/test-connection', {
            method: 'POST',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-CSRF-Token': csrf
            },
            body: formData.toString()
        })
        .then(function (response) {
            return response.json();
        })
        .then(function (data) {
            if (data.status === 'success') {
                resultSpan.innerHTML = '<span class="text-success"><i class="bi bi-check-circle me-1"></i>Connection successful</span>';
            } else {
                resultSpan.innerHTML = '<span class="text-danger"><i class="bi bi-x-circle me-1"></i>' + escapeHtml(data.message || 'Connection failed') + '</span>';
            }
        })
        .catch(function () {
            resultSpan.innerHTML = '<span class="text-danger"><i class="bi bi-x-circle me-1"></i>Request failed</span>';
        })
        .finally(function () {
            testBtn.disabled = false;
        });
    });
}

/* ---- AJAX SMTP Test ---- */

function initSMTPTest() {
    var testBtn = document.getElementById('test-smtp-btn');
    if (!testBtn) return;

    testBtn.addEventListener('click', function () {
        var resultSpan = document.getElementById('smtp-test-result');
        var emailInput = document.getElementById('test-email-addr');
        var csrf = getCSRFToken();

        if (!emailInput || !emailInput.value.trim()) {
            resultSpan.innerHTML = '<span class="text-danger"><i class="bi bi-x-circle me-1"></i>Enter a recipient email address</span>';
            if (emailInput) emailInput.focus();
            return;
        }

        testBtn.disabled = true;
        resultSpan.innerHTML = '<span class="text-muted"><span class="spinner-border spinner-border-sm me-1"></span>Sending test email...</span>';

        fetch('/admin/smtp/test', {
            method: 'POST',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-CSRF-Token': csrf
            },
            body: 'to=' + encodeURIComponent(emailInput.value.trim())
        })
        .then(function (response) {
            return response.json();
        })
        .then(function (data) {
            if (data.status === 'success') {
                resultSpan.innerHTML = '<span class="text-success"><i class="bi bi-check-circle me-1"></i>Test email sent successfully</span>';
            } else {
                resultSpan.innerHTML = '<span class="text-danger"><i class="bi bi-x-circle me-1"></i>' + escapeHtml(data.message || 'Failed to send') + '</span>';
            }
        })
        .catch(function () {
            resultSpan.innerHTML = '<span class="text-danger"><i class="bi bi-x-circle me-1"></i>Request failed</span>';
        })
        .finally(function () {
            testBtn.disabled = false;
        });
    });
}

/* ---- Dynamic Attribute Mapping Rows ---- */

var AD_ATTRS = [
    'sAMAccountName', 'userPrincipalName', 'mail', 'displayName',
    'givenName', 'sn', 'cn', 'distinguishedName', 'employeeID',
    'employeeNumber', 'department', 'title', 'telephoneNumber',
    'mobile', 'manager', 'memberOf', 'userAccountControl',
    'lockoutTime', 'pwdLastSet', 'accountExpires'
];

var FREEIPA_ATTRS = [
    'uid', 'mail', 'cn', 'displayName', 'givenName', 'sn',
    'employeeNumber', 'employeeType', 'departmentNumber', 'title',
    'telephoneNumber', 'mobile', 'manager', 'memberOf',
    'krbPrincipalName', 'nsAccountLock', 'krbLoginFailedCount',
    'krbLastPwdChange', 'krbPasswordExpiration'
];

var CANONICAL_NAMES = [
    'username', 'email', 'display_name', 'first_name', 'last_name',
    'employee_id', 'department', 'title', 'phone'
];

function initAttributeMappingRows() {
    var addBtn = document.getElementById('add-attr-mapping');
    var tbody = document.getElementById('attr-mappings-body');
    var typeSelect = document.getElementById('idp_type');
    var form = document.getElementById('idp-form');
    if (!addBtn || !tbody) return;

    function getDirectoryAttrs() {
        if (!typeSelect) return [];
        return typeSelect.value === 'ad' ? AD_ATTRS : typeSelect.value === 'freeipa' ? FREEIPA_ATTRS : [];
    }

    function buildCanonicalSelect(selectedValue) {
        var html = '<option value="">Select...</option>';
        CANONICAL_NAMES.forEach(function (name) {
            html += '<option value="' + name + '"' + (name === selectedValue ? ' selected' : '') + '>' + name + '</option>';
        });
        return html;
    }

    function buildDirectorySelect(selectedValue) {
        var attrs = getDirectoryAttrs();
        var html = '<option value="">Select...</option>';
        var found = false;
        attrs.forEach(function (attr) {
            var sel = attr === selectedValue ? ' selected' : '';
            if (attr === selectedValue) found = true;
            html += '<option value="' + attr + '"' + sel + '>' + attr + '</option>';
        });
        // If saved value isn't in the list, add it so it's not lost.
        if (selectedValue && !found) {
            html += '<option value="' + escapeHtml(selectedValue) + '" selected>' + escapeHtml(selectedValue) + '</option>';
        }
        return html;
    }

    // Populate directory attr dropdowns for existing rows on page load.
    function populateExistingRows() {
        var savedDirAttrs = form ? (form.dataset.savedDirAttrs || '').split(',') : [];
        var rows = tbody.querySelectorAll('.attr-mapping-row');
        rows.forEach(function (row, idx) {
            var dirSelect = row.querySelector('.directory-attr-select');
            if (dirSelect) {
                var savedVal = savedDirAttrs[idx] || '';
                dirSelect.innerHTML = buildDirectorySelect(savedVal);
            }
        });
    }

    populateExistingRows();

    // Rebuild directory selects when provider type changes.
    if (typeSelect) {
        typeSelect.addEventListener('change', function () {
            tbody.querySelectorAll('.directory-attr-select').forEach(function (sel) {
                var current = sel.value;
                sel.innerHTML = buildDirectorySelect(current);
            });
        });
    }

    addBtn.addEventListener('click', function () {
        var row = document.createElement('tr');
        row.className = 'attr-mapping-row';
        row.innerHTML =
            '<td><select class="form-select form-select-sm canonical-name-select" name="canonical_name[]">' +
            buildCanonicalSelect('') + '</select></td>' +
            '<td><select class="form-select form-select-sm directory-attr-select" name="directory_attr[]">' +
            buildDirectorySelect('') + '</select></td>' +
            '<td><button type="button" class="btn btn-sm btn-outline-danger remove-attr-mapping"><i class="bi bi-x"></i></button></td>';
        tbody.appendChild(row);
        row.querySelector('select').focus();

        // Update correlation source dropdown when mappings change.
        row.querySelector('.canonical-name-select').addEventListener('change', syncCorrelationSourceAttr);
        syncCorrelationSourceAttr();
    });

    tbody.addEventListener('click', function (e) {
        var removeBtn = e.target.closest('.remove-attr-mapping');
        if (removeBtn) {
            removeBtn.closest('tr').remove();
            syncCorrelationSourceAttr();
        }
    });

    // Listen for canonical name changes on existing rows.
    tbody.addEventListener('change', function (e) {
        if (e.target.classList.contains('canonical-name-select')) {
            syncCorrelationSourceAttr();
        }
    });

    // --- Correlation Rule Dropdowns ---

    function syncCorrelationSourceAttr() {
        var sourceSelect = document.getElementById('corr_source_attr');
        if (!sourceSelect) return;

        var currentVal = sourceSelect.value;
        var canonicals = [];
        tbody.querySelectorAll('.canonical-name-select').forEach(function (sel) {
            if (sel.value) canonicals.push(sel.value);
        });

        var html = '<option value="">Select...</option>';
        canonicals.forEach(function (name) {
            html += '<option value="' + name + '"' + (name === currentVal ? ' selected' : '') + '>' + name + '</option>';
        });
        sourceSelect.innerHTML = html;
    }

    // Initialize correlation source dropdown on page load.
    syncCorrelationSourceAttr();

    // Restore saved correlation source value.
    if (form) {
        var savedSource = form.dataset.savedSourceAttr || '';
        if (savedSource) {
            var sourceSelect = document.getElementById('corr_source_attr');
            var found = false;
            for (var i = 0; i < sourceSelect.options.length; i++) {
                if (sourceSelect.options[i].value === savedSource) { found = true; break; }
            }
            if (!found) {
                sourceSelect.insertAdjacentHTML('beforeend',
                    '<option value="' + escapeHtml(savedSource) + '">' + escapeHtml(savedSource) + '</option>');
            }
            sourceSelect.value = savedSource;
        }
    }
}

/* ---- Flash Auto-Dismiss ---- */

function initFlashAutoDismiss() {
    var flashMessages = document.querySelectorAll('.flash-message');
    if (flashMessages.length === 0) return;

    setTimeout(function () {
        flashMessages.forEach(function (el) {
            el.classList.add('fade-out');
            setTimeout(function () {
                var alert = bootstrap.Alert.getOrCreateInstance(el);
                if (alert) alert.close();
            }, 500);
        });
    }, 8000);
}

/* ---- View Group Members (Admin Groups) ---- */

function initViewGroupMembers() {
    var buttons = document.querySelectorAll('.view-members-btn');
    if (buttons.length === 0) return;

    buttons.forEach(function (btn) {
        btn.addEventListener('click', function () {
            var groupId = this.getAttribute('data-group-id');
            var groupDN = this.getAttribute('data-group-dn');

            var modal = new bootstrap.Modal(document.getElementById('membersModal'));
            document.getElementById('membersGroupDN').textContent = groupDN;
            document.getElementById('membersLoading').classList.remove('d-none');
            document.getElementById('membersError').classList.add('d-none');
            document.getElementById('membersContent').classList.add('d-none');
            document.getElementById('membersList').innerHTML = '';

            modal.show();

            fetch('/admin/groups/' + encodeURIComponent(groupId) + '/members', {
                headers: { 'Accept': 'application/json' }
            })
            .then(function (response) { return response.json(); })
            .then(function (data) {
                document.getElementById('membersLoading').classList.add('d-none');

                if (data.status !== 'success') {
                    document.getElementById('membersError').classList.remove('d-none');
                    document.getElementById('membersError').textContent = data.message || 'Failed to load members';
                    return;
                }

                document.getElementById('membersCount').textContent = data.count;
                var tbody = document.getElementById('membersList');
                var members = data.members || [];
                if (members.length === 0) {
                    tbody.innerHTML = '<tr><td class="text-muted">No members found</td></tr>';
                } else {
                    members.forEach(function (dn) {
                        var tr = document.createElement('tr');
                        var td = document.createElement('td');
                        var code = document.createElement('code');
                        code.className = 'small';
                        code.textContent = dn;
                        td.appendChild(code);
                        tr.appendChild(td);
                        tbody.appendChild(tr);
                    });
                }
                document.getElementById('membersContent').classList.remove('d-none');
            })
            .catch(function () {
                document.getElementById('membersLoading').classList.add('d-none');
                document.getElementById('membersError').classList.remove('d-none');
                document.getElementById('membersError').textContent = 'Request failed';
            });
        });
    });
}

/* ---- Dynamic Expiration Filter Rows ---- */

var FILTER_AD_ATTRS = [
    'distinguishedName', 'sAMAccountName', 'userPrincipalName', 'mail',
    'displayName', 'givenName', 'sn', 'cn', 'department', 'title',
    'employeeID', 'employeeNumber', 'memberOf', 'userAccountControl',
    'description', 'company', 'manager', 'physicalDeliveryOfficeName'
];

var FILTER_FREEIPA_ATTRS = [
    'dn', 'uid', 'mail', 'cn', 'displayName', 'givenName', 'sn',
    'departmentNumber', 'title', 'employeeNumber', 'employeeType',
    'memberOf', 'nsAccountLock', 'description', 'manager',
    'krbPrincipalName', 'objectClass'
];

function initExpirationFilters() {
    var addBtn = document.getElementById('add-expiration-filter');
    var tbody = document.getElementById('expiration-filters-body');
    var table = document.getElementById('expiration-filters-table');
    if (!addBtn || !tbody || !table) return;

    var providerType = table.getAttribute('data-provider-type') || '';

    function getFilterAttrs() {
        return providerType === 'ad' ? FILTER_AD_ATTRS : FILTER_FREEIPA_ATTRS;
    }

    function buildFilterAttrSelect(selectedValue) {
        var attrs = getFilterAttrs();
        var html = '<option value="">Select...</option>';
        var found = false;
        attrs.forEach(function (attr) {
            var sel = attr === selectedValue ? ' selected' : '';
            if (attr === selectedValue) found = true;
            html += '<option value="' + attr + '"' + sel + '>' + attr + '</option>';
        });
        if (selectedValue && !found) {
            html += '<option value="' + escapeHtml(selectedValue) + '" selected>' + escapeHtml(selectedValue) + '</option>';
        }
        return html;
    }

    // Populate existing filter attribute dropdowns on page load.
    tbody.querySelectorAll('.filter-attr-select').forEach(function (sel) {
        var saved = sel.getAttribute('data-saved-value') || '';
        sel.innerHTML = buildFilterAttrSelect(saved);
    });

    addBtn.addEventListener('click', function () {
        var row = document.createElement('tr');
        row.className = 'expiration-filter-row';
        row.innerHTML =
            '<td><select class="form-select form-select-sm filter-attr-select" name="filter_attribute[]">' +
            buildFilterAttrSelect('') + '</select></td>' +
            '<td><input type="text" class="form-control form-control-sm" name="filter_pattern[]" placeholder="e.g., OU=Service Accounts"></td>' +
            '<td><input type="text" class="form-control form-control-sm" name="filter_description[]" placeholder="e.g., Exclude service accounts"></td>' +
            '<td><button type="button" class="btn btn-sm btn-outline-danger remove-expiration-filter"><i class="bi bi-x"></i></button></td>';
        tbody.appendChild(row);
        row.querySelector('select').focus();
    });

    tbody.addEventListener('click', function (e) {
        var removeBtn = e.target.closest('.remove-expiration-filter');
        if (removeBtn) {
            removeBtn.closest('tr').remove();
        }
    });

    // Cron preset buttons
    document.querySelectorAll('.cron-preset').forEach(function (btn) {
        btn.addEventListener('click', function () {
            var cronInput = document.getElementById('cron_schedule');
            if (cronInput) {
                cronInput.value = this.getAttribute('data-cron');
            }
        });
    });
}

/* ---- AJAX Dry Run (Expiration Test Filters) ---- */

function initDryRun() {
    var btn = document.getElementById('dry-run-btn');
    if (!btn) return;

    btn.addEventListener('click', function () {
        var idpID = btn.getAttribute('data-idp-id');
        var csrf = getCSRFToken();
        var modal = new bootstrap.Modal(document.getElementById('dryRunModal'));

        document.getElementById('dry-run-loading').classList.remove('d-none');
        document.getElementById('dry-run-error').classList.add('d-none');
        document.getElementById('dry-run-results').classList.add('d-none');
        document.getElementById('dry-run-tbody').innerHTML = '';

        modal.show();

        fetch('/admin/idp/' + encodeURIComponent(idpID) + '/expiration/dry-run', {
            method: 'POST',
            headers: { 'Accept': 'application/json', 'X-CSRF-Token': csrf }
        })
        .then(function (r) { return r.json(); })
        .then(function (data) {
            document.getElementById('dry-run-loading').classList.add('d-none');

            if (data.status !== 'success') {
                var errEl = document.getElementById('dry-run-error');
                errEl.textContent = data.message || 'Scan failed';
                errEl.classList.remove('d-none');
                return;
            }

            document.getElementById('dry-run-total').textContent = data.total_users;
            document.getElementById('dry-run-excluded').textContent = data.excluded_count;
            document.getElementById('dry-run-eligible').textContent = data.eligible_count;

            var tbody = document.getElementById('dry-run-tbody');
            var users = data.users || [];

            if (users.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted py-3">No users with expiring passwords found within the configured threshold.</td></tr>';
            } else {
                users.forEach(function (u) {
                    var tr = document.createElement('tr');
                    if (u.excluded) {
                        tr.className = 'table-danger';
                    }

                    // Store sort values and DN as data attributes.
                    tr.setAttribute('data-dn', u.dn || '');
                    tr.setAttribute('data-sort-username', (u.username || '').toLowerCase());
                    tr.setAttribute('data-sort-email', (u.email || '').toLowerCase());
                    tr.setAttribute('data-sort-expiration', u.expiration_epoch || 0);
                    tr.setAttribute('data-sort-days', u.days_remaining);
                    tr.setAttribute('data-sort-filter', (u.filter_match || '').toLowerCase());
                    tr.style.cursor = 'pointer';

                    var tdUser = document.createElement('td');
                    tdUser.className = 'fw-semibold';
                    tdUser.textContent = u.username;

                    var tdEmail = document.createElement('td');
                    tdEmail.textContent = u.email || '(none)';
                    if (!u.email) tdEmail.className = 'text-muted fst-italic';

                    var tdExpiry = document.createElement('td');
                    tdExpiry.textContent = u.expiration_date;

                    var tdDays = document.createElement('td');
                    tdDays.className = 'text-center';
                    var badge = document.createElement('span');
                    badge.className = 'badge ' + (u.days_remaining <= 3 ? 'bg-danger' : u.days_remaining <= 7 ? 'bg-warning text-dark' : 'bg-info');
                    badge.textContent = u.days_remaining;
                    tdDays.appendChild(badge);

                    var tdFilter = document.createElement('td');
                    if (u.excluded && u.filter_match) {
                        var filterBadge = document.createElement('span');
                        filterBadge.className = 'badge bg-danger-subtle text-danger';
                        filterBadge.textContent = u.filter_match;
                        tdFilter.appendChild(filterBadge);
                    }

                    tr.appendChild(tdUser);
                    tr.appendChild(tdEmail);
                    tr.appendChild(tdExpiry);
                    tr.appendChild(tdDays);
                    tr.appendChild(tdFilter);
                    tbody.appendChild(tr);
                });

                // Wire up sortable column headers and row clicks.
                initDryRunTableSort();
                initDryRunRowClick(idpID);
            }

            // Hide attribute panel from a previous run.
            document.getElementById('dry-run-attr-panel').classList.add('d-none');
            document.getElementById('dry-run-results').classList.remove('d-none');
        })
        .catch(function (err) {
            document.getElementById('dry-run-loading').classList.add('d-none');
            var errEl = document.getElementById('dry-run-error');
            errEl.textContent = 'Request failed: ' + err.message;
            errEl.classList.remove('d-none');
        });
    });
}

/* ---- Dry Run Table Sorting ---- */

function initDryRunTableSort() {
    var table = document.getElementById('dry-run-table');
    if (!table) return;

    var headers = table.querySelectorAll('th.sortable');
    var currentKey = null;
    var ascending = true;

    function sortByColumn(th) {
        var key = th.getAttribute('data-sort-key');
        var type = th.getAttribute('data-sort-type');

        if (currentKey === key) {
            ascending = !ascending;
        } else {
            currentKey = key;
            ascending = true;
        }

        headers.forEach(function (h) {
            var icon = h.querySelector('i');
            if (icon) icon.className = 'bi bi-chevron-expand text-muted small';
        });
        var activeIcon = th.querySelector('i');
        if (activeIcon) {
            activeIcon.className = ascending ? 'bi bi-chevron-up small' : 'bi bi-chevron-down small';
        }

        var tbody = document.getElementById('dry-run-tbody');
        var rows = Array.from(tbody.querySelectorAll('tr[data-sort-username]'));

        rows.sort(function (a, b) {
            var aVal = a.getAttribute('data-sort-' + key) || '';
            var bVal = b.getAttribute('data-sort-' + key) || '';

            if (type === 'number') {
                return ascending ? (parseFloat(aVal) || 0) - (parseFloat(bVal) || 0) : (parseFloat(bVal) || 0) - (parseFloat(aVal) || 0);
            }
            if (aVal < bVal) return ascending ? -1 : 1;
            if (aVal > bVal) return ascending ? 1 : -1;
            return 0;
        });

        rows.forEach(function (row) { tbody.appendChild(row); });
    }

    headers.forEach(function (th) {
        th.style.cursor = 'pointer';
        th.addEventListener('click', function () { sortByColumn(th); });
    });

    // Default sort: username ascending.
    var usernameHeader = table.querySelector('th[data-sort-key="username"]');
    if (usernameHeader) {
        sortByColumn(usernameHeader);
    }
}

/* ---- Dry Run Row Click — Show User Attributes ---- */

function initDryRunRowClick(idpID) {
    var tbody = document.getElementById('dry-run-tbody');
    var panel = document.getElementById('dry-run-attr-panel');
    var closeBtn = document.getElementById('dry-run-attr-close');
    if (!tbody || !panel) return;

    closeBtn.addEventListener('click', function () {
        panel.classList.add('d-none');
        tbody.querySelectorAll('tr.table-primary, tr.table-info').forEach(function (r) {
            // Restore original class (danger for excluded, nothing for eligible).
            r.classList.remove('table-primary', 'table-info');
        });
    });

    tbody.addEventListener('click', function (e) {
        var row = e.target.closest('tr[data-dn]');
        if (!row) return;

        var dn = row.getAttribute('data-dn');
        if (!dn) return;

        // Highlight selected row.
        tbody.querySelectorAll('tr.table-primary, tr.table-info').forEach(function (r) {
            r.classList.remove('table-primary', 'table-info');
        });
        if (!row.classList.contains('table-danger')) {
            row.classList.add('table-info');
        } else {
            row.classList.add('table-primary');
        }

        // Show panel, loading state.
        var loading = document.getElementById('dry-run-attr-loading');
        var errorEl = document.getElementById('dry-run-attr-error');
        var content = document.getElementById('dry-run-attr-content');
        var attrDn = document.getElementById('dry-run-attr-dn');
        var attrTbody = document.getElementById('dry-run-attr-tbody');

        panel.classList.remove('d-none');
        loading.classList.remove('d-none');
        errorEl.classList.add('d-none');
        content.classList.add('d-none');
        attrDn.textContent = dn;

        fetch('/admin/idp/' + encodeURIComponent(idpID) + '/entry?dn=' + encodeURIComponent(dn), {
            headers: { 'Accept': 'application/json' }
        })
        .then(function (r) { return r.json(); })
        .then(function (data) {
            loading.classList.add('d-none');
            if (data.error) {
                document.getElementById('dry-run-attr-error-msg').textContent = data.error;
                errorEl.classList.remove('d-none');
                return;
            }

            attrTbody.innerHTML = '';
            var attributes = data.attributes || [];
            attributes.forEach(function (attr) {
                var tr = document.createElement('tr');
                var tdName = document.createElement('td');
                tdName.className = 'fw-semibold text-nowrap';
                var code = document.createElement('code');
                code.textContent = attr.name;
                tdName.appendChild(code);

                var tdValues = document.createElement('td');
                tdValues.className = 'text-break small';
                var values = attr.values || [];
                values.forEach(function (val, idx) {
                    if (idx > 0) tdValues.appendChild(document.createElement('br'));
                    tdValues.appendChild(document.createTextNode(val));
                });

                tr.appendChild(tdName);
                tr.appendChild(tdValues);
                attrTbody.appendChild(tr);
            });

            content.classList.remove('d-none');
        })
        .catch(function (err) {
            loading.classList.add('d-none');
            document.getElementById('dry-run-attr-error-msg').textContent = 'Failed to load: ' + err.message;
            errorEl.classList.remove('d-none');
        });
    });
}

/* ---- AJAX Run Now (Expiration) ---- */

function initRunNow() {
    var runBtn = document.getElementById('run-now-btn');
    if (!runBtn) return;

    runBtn.addEventListener('click', function () {
        var resultSpan = document.getElementById('run-now-result');
        var idpID = runBtn.getAttribute('data-idp-id');
        var csrf = getCSRFToken();

        runBtn.disabled = true;
        resultSpan.innerHTML = '<span class="text-muted"><span class="spinner-border spinner-border-sm me-1"></span>Running scan...</span>';

        fetch('/admin/idp/' + encodeURIComponent(idpID) + '/expiration/run', {
            method: 'POST',
            headers: {
                'Accept': 'application/json',
                'X-CSRF-Token': csrf
            }
        })
        .then(function (response) { return response.json(); })
        .then(function (data) {
            if (data.status === 'success') {
                resultSpan.innerHTML = '<span class="text-success"><i class="bi bi-check-circle me-1"></i>' + escapeHtml(data.message) + '</span>';
            } else {
                resultSpan.innerHTML = '<span class="text-danger"><i class="bi bi-x-circle me-1"></i>' + escapeHtml(data.message || 'Scan failed') + '</span>';
            }
        })
        .catch(function () {
            resultSpan.innerHTML = '<span class="text-danger"><i class="bi bi-x-circle me-1"></i>Request failed</span>';
        })
        .finally(function () {
            runBtn.disabled = false;
        });
    });
}

/* ---- Random Password Policy Toggles (Admin IDP Form) ---- */

function initPasswordPolicyToggles() {
    var group = document.getElementById('pw-policy-group');
    if (!group) return;

    var checkboxes = group.querySelectorAll('.pw-policy-check');
    var specialCheck = document.getElementById('password_allow_special');
    var specialInput = document.getElementById('password_special_chars');
    var errorEl = document.getElementById('pw-policy-error');

    function anyChecked() {
        return Array.from(checkboxes).some(function (cb) { return cb.checked; });
    }

    function updateSpecialField() {
        if (specialInput) {
            specialInput.disabled = !specialCheck.checked;
        }
    }

    checkboxes.forEach(function (cb) {
        cb.addEventListener('change', function () {
            if (!cb.checked && !anyChecked()) {
                // Trying to uncheck the last one — prevent it.
                cb.checked = true;
                if (errorEl) {
                    errorEl.classList.remove('d-none');
                    setTimeout(function () { errorEl.classList.add('d-none'); }, 3000);
                }
                return;
            }
            if (errorEl) errorEl.classList.add('d-none');
            if (cb === specialCheck) updateSpecialField();
        });
    });

    // Set initial state on page load.
    updateSpecialField();
}

/* ---- Utility Functions ---- */

function getCSRFToken() {
    var input = document.querySelector('input[name="gorilla.csrf.Token"]');
    if (input) return input.value;
    var meta = document.querySelector('meta[name="csrf-token"]');
    if (meta) return meta.getAttribute('content');
    return '';
}

function escapeHtml(text) {
    var div = document.createElement('div');
    div.appendChild(document.createTextNode(text));
    return div.innerHTML;
}

/* ---- Unsaved Changes Warning (Admin IDP Form) ---- */

function initUnsavedChangesWarning() {
    var form = document.getElementById('idp-form');
    if (!form) return;

    var dirty = false;
    form.addEventListener('change', function() { dirty = true; });
    form.addEventListener('input', function() { dirty = true; });
    form.addEventListener('submit', function() { dirty = false; });

    // Add/remove attribute mapping rows change form data but don't fire input/change.
    form.addEventListener('click', function(e) {
        if (e.target.closest('#add-attr-mapping') || e.target.closest('.remove-attr-mapping')) {
            dirty = true;
        }
    });

    window.addEventListener('beforeunload', function(e) {
        if (dirty) { e.preventDefault(); e.returnValue = ''; }
    });
}
