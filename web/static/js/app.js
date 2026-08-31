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
    initMarkdownToolbars();
    initDescriptionLinks();
    initIDPArrangement();
    initGroupModals();
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

/* ---- Password Policy Validation ---- */

/*
 * Evaluates the rules the directory reported. Active Directory fixes its
 * complexity rule at three of five categories plus a name check (MS-ADTS
 * 3.1.1.13.1); FreeIPA makes the category count configurable and the name check
 * a separate switch, so both are read from the markup rather than assumed. This
 * is guidance only — the directory still decides, and it alone knows the
 * password history.
 */
function evaluatePasswordRules(rules, value) {
    var results = {};

    results.length = value.length >= rules.minLength;

    if (rules.minCategories > 0) {
        var categories = 0;
        if (/[A-Z]/.test(value)) categories++;
        if (/[a-z]/.test(value)) categories++;
        if (/[0-9]/.test(value)) categories++;
        if (/[^A-Za-z0-9]/.test(value)) categories++;
        results.categories = categories >= rules.minCategories;
    }

    if (rules.forbidUserName) {
        var lower = value.toLowerCase();
        var ok = true;
        if (rules.accountName && rules.accountName.length >= 3) {
            if (lower.indexOf(rules.accountName.toLowerCase()) !== -1) ok = false;
        }
        (rules.displayName || '').split(/[,.\-_#\s\t]+/).forEach(function (token) {
            if (token.length >= 3 && lower.indexOf(token.toLowerCase()) !== -1) ok = false;
        });
        results.name = ok;
    }

    return results;
}

function readPasswordRules(form) {
    var el = form.querySelector('.password-rules');
    if (!el) return null;
    return {
        element: el,
        minLength: parseInt(el.getAttribute('data-min-length'), 10) || 0,
        minCategories: parseInt(el.getAttribute('data-min-categories'), 10) || 0,
        forbidUserName: el.getAttribute('data-forbid-username') === '1',
        accountName: el.getAttribute('data-account-name') || '',
        displayName: el.getAttribute('data-display-name') || ''
    };
}

function renderPasswordRules(rules, results, touched) {
    var allMet = true;
    rules.element.querySelectorAll('.password-rule').forEach(function (li) {
        var met = results[li.getAttribute('data-rule')];
        if (met === false) allMet = false;
        var icon = li.querySelector('i');
        if (!touched) {
            li.className = 'password-rule';
            if (icon) icon.className = 'bi bi-circle me-1';
            return;
        }
        li.className = 'password-rule ' + (met ? 'rule-met' : 'rule-unmet');
        if (icon) icon.className = met ? 'bi bi-check-circle-fill me-1' : 'bi bi-circle me-1';
    });
    return allMet;
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
        var rules = readPasswordRules(form);

        function validate() {
            var newVal = newPw.value;
            var confirmVal = confirmPw.value;

            // Absent policy data leaves the form behaving exactly as before.
            var policyMet = true;
            if (rules) {
                policyMet = renderPasswordRules(rules, evaluatePasswordRules(rules, newVal), newVal.length > 0);
            }

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
                submitBtn.disabled = !policyMet;
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
                alertEl.classList.remove('d-none', 'alert-success', 'alert-warning', 'alert-danger');
                if (data.status === 'success') {
                    alertEl.classList.add('alert-success');
                    alertEl.innerHTML = '<i class="bi bi-check-circle me-1"></i>' + escapeHtml(data.message || 'Connection successful');
                } else if (data.status === 'warning') {
                    alertEl.classList.add('alert-warning');
                    alertEl.innerHTML = '<i class="bi bi-exclamation-triangle me-1"></i>' + escapeHtml(data.message);
                } else {
                    alertEl.classList.add('alert-danger');
                    alertEl.innerHTML = '<i class="bi bi-x-circle me-1"></i>' + escapeHtml(data.message || 'Connection failed');
                }
            })
            .catch(function () {
                alertEl.classList.remove('d-none', 'alert-success', 'alert-warning', 'alert-danger');
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

        // Weblink providers have no directory: "test" just opens the target URL.
        // window.open must run synchronously in the click handler to avoid popup blocking.
        var typeSelect = form.querySelector('[name="provider_type"]');
        if (typeSelect && typeSelect.value === 'weblink') {
            var urlInput = form.querySelector('[name="weblink_url"]');
            var url = urlInput ? urlInput.value.trim() : '';
            if (!/^https?:\/\//i.test(url)) {
                resultSpan.innerHTML = '<span class="text-danger"><i class="bi bi-x-circle me-1"></i>Enter a valid http:// or https:// URL</span>';
                return;
            }
            window.open(url, '_blank', 'noopener,noreferrer');
            resultSpan.innerHTML = '<span class="text-success"><i class="bi bi-check-circle me-1"></i>Opened in a new window</span>';
            return;
        }

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
            } else if (data.status === 'warning') {
                resultSpan.innerHTML = '<span class="text-warning-emphasis"><i class="bi bi-exclamation-triangle me-1"></i>' + escapeHtml(data.message) + '</span>';
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

        while (sourceSelect.options.length > 0) { sourceSelect.remove(0); }
        var defaultOpt = document.createElement('option');
        defaultOpt.value = '';
        defaultOpt.textContent = 'Select...';
        sourceSelect.appendChild(defaultOpt);
        canonicals.forEach(function (name) {
            var opt = document.createElement('option');
            opt.value = name;
            opt.textContent = name;
            if (name === currentVal) { opt.selected = true; }
            sourceSelect.appendChild(opt);
        });
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
        document.getElementById('dry-run-expired-tbody').innerHTML = '';

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

            // --- Expiring Soon tab ---
            document.getElementById('dry-run-total').textContent = data.total_users;
            document.getElementById('dry-run-excluded').textContent = data.excluded_count;
            document.getElementById('dry-run-eligible').textContent = data.eligible_count;
            document.getElementById('dry-run-warning-badge').textContent = data.eligible_count;

            var tbody = document.getElementById('dry-run-tbody');
            var users = data.users || [];

            if (users.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted py-3">No users with expiring passwords found within the configured threshold.</td></tr>';
            } else {
                users.forEach(function (u) {
                    var tr = document.createElement('tr');
                    if (u.excluded) tr.className = 'table-danger';
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

                initDryRunTableSort('dry-run-table', 'dry-run-tbody');
                initDryRunRowClick(idpID, 'dry-run-tbody');
            }

            // --- Already Expired tab ---
            var expiredTotal = data.expired_total || 0;
            var expiredExcluded = data.expired_excluded_count || 0;
            var expiredEligible = data.expired_eligible_count || 0;
            var expiredUsers = data.expired_users || [];

            document.getElementById('dry-run-expired-badge').textContent = expiredEligible;

            var disabledMsg = document.getElementById('dry-run-expired-disabled');
            var expiredContent = document.getElementById('dry-run-expired-content');

            if (expiredTotal === 0 && expiredUsers.length === 0 && data.expired_total === undefined) {
                // days_after_expiration is 0 (disabled)
                disabledMsg.classList.remove('d-none');
                expiredContent.classList.add('d-none');
            } else {
                disabledMsg.classList.add('d-none');
                expiredContent.classList.remove('d-none');

                document.getElementById('dry-run-expired-total').textContent = expiredTotal;
                document.getElementById('dry-run-expired-excluded').textContent = expiredExcluded;
                document.getElementById('dry-run-expired-eligible').textContent = expiredEligible;

                var expiredTbody = document.getElementById('dry-run-expired-tbody');

                if (expiredUsers.length === 0) {
                    expiredTbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted py-3">No already-expired users found.</td></tr>';
                } else {
                    expiredUsers.forEach(function (u) {
                        var tr = document.createElement('tr');
                        if (u.excluded) tr.className = 'table-danger';
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
                        var expBadge = document.createElement('span');
                        expBadge.className = 'badge bg-danger';
                        expBadge.textContent = u.days_remaining; // positive "days expired" value
                        tdDays.appendChild(expBadge);

                        var tdFilter = document.createElement('td');
                        if (u.excluded && u.filter_match) {
                            var filterBadge2 = document.createElement('span');
                            filterBadge2.className = 'badge bg-danger-subtle text-danger';
                            filterBadge2.textContent = u.filter_match;
                            tdFilter.appendChild(filterBadge2);
                        }

                        tr.appendChild(tdUser);
                        tr.appendChild(tdEmail);
                        tr.appendChild(tdExpiry);
                        tr.appendChild(tdDays);
                        tr.appendChild(tdFilter);
                        expiredTbody.appendChild(tr);
                    });

                    initDryRunTableSort('dry-run-expired-table', 'dry-run-expired-tbody');
                    initDryRunRowClick(idpID, 'dry-run-expired-tbody');
                }
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

function initDryRunTableSort(tableId, tbodyId) {
    var table = document.getElementById(tableId);
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

        var tbody = document.getElementById(tbodyId);
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

function initDryRunRowClick(idpID, tbodyId) {
    var tbody = document.getElementById(tbodyId);
    var panel = document.getElementById('dry-run-attr-panel');
    var closeBtn = document.getElementById('dry-run-attr-close');
    if (!tbody || !panel) return;

    // Only bind the close button once.
    if (!closeBtn._bound) {
        closeBtn._bound = true;
        closeBtn.addEventListener('click', function () {
            panel.classList.add('d-none');
            ['dry-run-tbody', 'dry-run-expired-tbody'].forEach(function (id) {
                var b = document.getElementById(id);
                if (b) b.querySelectorAll('tr.table-primary, tr.table-info').forEach(function (r) {
                    r.classList.remove('table-primary', 'table-info');
                });
            });
        });
    }

    tbody.addEventListener('click', function (e) {
        var row = e.target.closest('tr[data-dn]');
        if (!row) return;

        var dn = row.getAttribute('data-dn');
        if (!dn) return;

        // Clear highlights from both tables.
        ['dry-run-tbody', 'dry-run-expired-tbody'].forEach(function (id) {
            var b = document.getElementById(id);
            if (b) b.querySelectorAll('tr.table-primary, tr.table-info').forEach(function (r) {
                r.classList.remove('table-primary', 'table-info');
            });
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

    var modalEl = document.getElementById('runNowModal');
    var modal = modalEl ? new bootstrap.Modal(modalEl) : null;
    var testRadio = document.getElementById('run-now-mode-test');
    var fullRadio = document.getElementById('run-now-mode-full');
    var testEmailInput = document.getElementById('run-now-test-email');
    var confirmBtn = document.getElementById('run-now-confirm-btn');
    var confirmSpinner = document.getElementById('run-now-confirm-spinner');
    var errorEl = document.getElementById('run-now-modal-error');

    function updateTestEmailState() {
        if (testEmailInput) testEmailInput.disabled = !(testRadio && testRadio.checked);
    }
    if (testRadio) testRadio.addEventListener('change', updateTestEmailState);
    if (fullRadio) fullRadio.addEventListener('change', updateTestEmailState);

    runBtn.addEventListener('click', function () {
        if (errorEl) errorEl.classList.add('d-none');
        if (modal) modal.show();
    });

    if (!confirmBtn) return;
    confirmBtn.addEventListener('click', function () {
        var resultSpan = document.getElementById('run-now-result');
        var idpID = runBtn.getAttribute('data-idp-id');
        var csrf = getCSRFToken();
        var testEmail = '';

        if (testRadio && testRadio.checked) {
            testEmail = (testEmailInput.value || '').trim();
            if (!testEmail) {
                errorEl.textContent = 'Enter an email address to send the test run to.';
                errorEl.classList.remove('d-none');
                return;
            }
        }
        if (errorEl) errorEl.classList.add('d-none');

        var body = new URLSearchParams();
        if (testEmail) body.set('test_email', testEmail);

        confirmBtn.disabled = true;
        if (confirmSpinner) confirmSpinner.classList.remove('d-none');
        resultSpan.innerHTML = '<span class="text-muted"><span class="spinner-border spinner-border-sm me-1"></span>Running scan...</span>';

        fetch('/admin/idp/' + encodeURIComponent(idpID) + '/expiration/run', {
            method: 'POST',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-CSRF-Token': csrf
            },
            body: body.toString()
        })
        .then(function (response) { return response.json(); })
        .then(function (data) {
            if (data.status === 'success') {
                resultSpan.innerHTML = '<span class="text-success"><i class="bi bi-check-circle me-1"></i>' + escapeHtml(data.message) + '</span>';
                if (modal) modal.hide();
            } else {
                resultSpan.innerHTML = '';
                errorEl.textContent = data.message || 'Scan failed';
                errorEl.classList.remove('d-none');
            }
        })
        .catch(function () {
            resultSpan.innerHTML = '';
            errorEl.textContent = 'Request failed';
            errorEl.classList.remove('d-none');
        })
        .finally(function () {
            confirmBtn.disabled = false;
            if (confirmSpinner) confirmSpinner.classList.add('d-none');
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

/* ---- Markdown Toolbar ---- */

function initMarkdownToolbars() {
    document.querySelectorAll('[data-md-editor]').forEach(function(editor) {
        var textarea = editor.querySelector('textarea');
        if (!textarea) return;

        editor.querySelectorAll('[data-md-action]').forEach(function(btn) {
            btn.addEventListener('click', function() {
                applyMarkdownAction(textarea, btn.getAttribute('data-md-action'));
            });
        });
    });
}

// mdReplace swaps the [start, end) range for text and leaves the caret selecting
// [selStart, selEnd) relative to the start of the inserted text.
function mdReplace(el, start, end, text, selStart, selEnd) {
    el.setRangeText(text, start, end, 'end');
    el.focus();
    el.setSelectionRange(start + selStart, start + selEnd);
    el.dispatchEvent(new Event('input', { bubbles: true }));
}

function applyMarkdownAction(el, action) {
    var start = el.selectionStart;
    var end = el.selectionEnd;
    var selected = el.value.slice(start, end);

    var wrappers = {
        bold: { open: '**', close: '**', placeholder: 'bold text' },
        italic: { open: '*', close: '*', placeholder: 'italic text' },
        code: { open: '`', close: '`', placeholder: 'code' },
        // Raw HTML, so only offered on fields rendered with inline HTML enabled.
        underline: { open: '<u>', close: '</u>', placeholder: 'underlined text' }
    };

    if (wrappers[action]) {
        var w = wrappers[action];
        var body = selected || w.placeholder;
        mdReplace(el, start, end, w.open + body + w.close,
            w.open.length, w.open.length + body.length);
        return;
    }

    if (action === 'link') {
        var label = selected || 'link text';
        var out = '[' + label + '](https://)';
        // Select the URL so the next keystroke replaces it.
        mdReplace(el, start, end, out, label.length + 3, out.length - 1);
        return;
    }

    if (action === 'ul' || action === 'ol') {
        // Expand the range to whole lines so prefixes land in column 0.
        var lineStart = el.value.lastIndexOf('\n', start - 1) + 1;
        var lineEnd = el.value.indexOf('\n', end);
        if (lineEnd === -1) lineEnd = el.value.length;

        var block = el.value.slice(lineStart, lineEnd) || 'list item';
        var n = 0;
        var prefixed = block.split('\n').map(function(line) {
            n++;
            return (action === 'ul' ? '- ' : n + '. ') + line;
        }).join('\n');

        // A list needs a blank line before it to start a new block.
        var lead = (lineStart > 0 && el.value[lineStart - 1] !== '\n') ? '\n' : '';
        mdReplace(el, lineStart, lineEnd, lead + prefixed, lead.length, lead.length + prefixed.length);
    }
}

/* ---- Markdown Links in IDP Descriptions ---- */

// Descriptions are rendered server-side, so links get their target and click
// behaviour wired up here rather than in the Markdown output.
function initDescriptionLinks() {
    document.querySelectorAll('.idp-description a').forEach(function(link) {
        link.setAttribute('target', '_blank');
        link.setAttribute('rel', 'noopener noreferrer');
        // Inside a selectable provider card, following the link must not also
        // trigger the card's "sign in with this provider" handler.
        link.addEventListener('click', function(e) {
            e.stopPropagation();
        });
    });
}

/* ---- Provider Group Arrangement (drag and drop) ---- */

function initIDPArrangement() {
    var root = document.getElementById('arrangement');
    if (!root) return;

    var saveBtn = document.getElementById('save-arrangement');
    var hint = document.getElementById('arrange-hint');
    var groupList = document.getElementById('group-list');

    // Chromium cancels a drag if the DOM is mutated inside `dragstart`, and
    // again if the source element stops being rendered. So nothing moves until
    // `dragover`, the source is only dimmed, and a drag that ends without a
    // drop is rewound to where it started.
    var dragged = null;
    var originParent = null;
    var originNext = null;
    var dropped = false;

    function markDirty() {
        if (saveBtn.disabled) {
            saveBtn.disabled = false;
            if (hint) hint.textContent = 'Unsaved changes.';
        }
    }

    function isChipDrag() {
        return dragged !== null && dragged.classList.contains('idp-chip');
    }

    function isGroupDrag() {
        return dragged !== null && dragged.classList.contains('group-card');
    }

    function beginDrag(el, e) {
        dragged = el;
        originParent = el.parentElement;
        originNext = el.nextElementSibling;
        dropped = false;

        e.dataTransfer.effectAllowed = 'move';
        // Firefox requires data to be set for the drag to start.
        e.dataTransfer.setData('text/plain', el.dataset.idpId || el.dataset.groupId || '');
        // Dimming has to wait a tick, or the browser snapshots a faded drag image.
        window.setTimeout(function () {
            if (dragged === el) el.classList.add('drag-ghost');
        }, 0);
    }

    function endDrag() {
        if (!dragged) return;
        var el = dragged;
        el.classList.remove('drag-ghost');
        root.querySelectorAll('.dropzone-active').forEach(function (zone) {
            zone.classList.remove('dropzone-active');
        });

        // Escape, or a release outside any list, rewinds the live reordering.
        if (!dropped) {
            if (originParent) originParent.insertBefore(el, originNext);
        } else if (el.parentElement !== originParent || el.nextElementSibling !== originNext) {
            markDirty();
        }

        dragged = null;
        originParent = null;
        originNext = null;
        dropped = false;
    }

    // Slots the dragged element before the first item whose midpoint is below
    // the pointer, or at the end of the list.
    function moveDragged(container, selector, y) {
        var items = container.querySelectorAll(selector);
        for (var i = 0; i < items.length; i++) {
            if (items[i] === dragged) continue;
            var box = items[i].getBoundingClientRect();
            if (y < box.top + box.height / 2) {
                container.insertBefore(dragged, items[i]);
                return;
            }
        }
        container.appendChild(dragged);
    }

    // Providers are dragged between the dropzone lists.
    root.querySelectorAll('.idp-chip').forEach(function (chip) {
        chip.addEventListener('dragstart', function (e) {
            beginDrag(chip, e);
            // Dragging a chip must not also start a drag of its group card.
            e.stopPropagation();
        });
        chip.addEventListener('dragend', function (e) {
            // Otherwise the enclosing card's dragend handler runs as well.
            e.stopPropagation();
            endDrag();
        });
    });

    root.querySelectorAll('.idp-dropzone').forEach(function (zone) {
        // Safari and Firefox only honour a drop target if dragenter is
        // cancelled as well as dragover.
        zone.addEventListener('dragenter', function (e) {
            if (!isChipDrag()) return;
            e.preventDefault();
        });
        zone.addEventListener('dragover', function (e) {
            if (!isChipDrag()) return;
            e.preventDefault();
            e.dataTransfer.dropEffect = 'move';
            zone.classList.add('dropzone-active');
            moveDragged(zone, '.idp-chip', e.clientY);
        });
        zone.addEventListener('dragleave', function (e) {
            // dragleave also fires when the pointer crosses onto a child.
            if (e.relatedTarget && zone.contains(e.relatedTarget)) return;
            zone.classList.remove('dropzone-active');
        });
        zone.addEventListener('drop', function (e) {
            if (!isChipDrag()) return;
            e.preventDefault();
            e.stopPropagation();
            dropped = true;
        });
    });

    // Group cards are dragged to reorder the groups themselves.
    if (groupList) {
        groupList.querySelectorAll('.group-card').forEach(function (card) {
            card.addEventListener('dragstart', function (e) {
                beginDrag(card, e);
            });
            card.addEventListener('dragend', function () {
                endDrag();
            });
        });

        groupList.addEventListener('dragenter', function (e) {
            if (!isGroupDrag()) return;
            e.preventDefault();
        });
        groupList.addEventListener('dragover', function (e) {
            if (!isGroupDrag()) return;
            e.preventDefault();
            e.dataTransfer.dropEffect = 'move';
            moveDragged(groupList, '.group-card', e.clientY);
        });
        groupList.addEventListener('drop', function (e) {
            if (!isGroupDrag()) return;
            e.preventDefault();
            dropped = true;
        });
    }

    // Keyboard/pointer fallback so arranging never requires dragging.
    root.addEventListener('click', function (e) {
        var chipBtn = e.target.closest('[data-idp-move]');
        if (chipBtn) {
            if (moveChip(chipBtn.closest('.idp-chip'), chipBtn.dataset.idpMove)) markDirty();
            return;
        }
        var groupBtn = e.target.closest('[data-group-move]');
        if (groupBtn && groupList) {
            if (moveGroup(groupBtn.closest('.group-card'), groupBtn.dataset.groupMove)) markDirty();
        }
    });

    // Past the edge of its list a provider hops into the neighbouring group, so
    // every placement the drag UI allows is reachable without a mouse.
    function moveChip(chip, direction) {
        if (!chip) return false;
        var zone = chip.parentElement;
        var chips = Array.prototype.slice.call(zone.querySelectorAll('.idp-chip'));
        var idx = chips.indexOf(chip);
        if (direction === 'up' && idx > 0) {
            zone.insertBefore(chip, chips[idx - 1]);
            return true;
        }
        if (direction === 'down' && idx > -1 && idx < chips.length - 1) {
            zone.insertBefore(chips[idx + 1], chip);
            return true;
        }

        var zones = Array.prototype.slice.call(root.querySelectorAll('.idp-dropzone'));
        var z = zones.indexOf(zone);
        if (direction === 'up' && z > 0) {
            zones[z - 1].appendChild(chip);
            return true;
        }
        if (direction === 'down' && z > -1 && z < zones.length - 1) {
            zones[z + 1].insertBefore(chip, zones[z + 1].firstElementChild);
            return true;
        }
        return false;
    }

    function moveGroup(card, direction) {
        if (!card) return false;
        var cards = Array.prototype.slice.call(groupList.querySelectorAll('.group-card'));
        var idx = cards.indexOf(card);
        if (direction === 'up' && idx > 0) {
            groupList.insertBefore(card, cards[idx - 1]);
            return true;
        }
        if (direction === 'down' && idx > -1 && idx < cards.length - 1) {
            groupList.insertBefore(cards[idx + 1], card);
            return true;
        }
        return false;
    }

    saveBtn.addEventListener('click', function () {
        var payload = {
            group_order: [],
            sections: []
        };

        root.querySelectorAll('.idp-dropzone').forEach(function (zone) {
            var raw = zone.dataset.groupId;
            var groupID = raw === '' ? null : parseInt(raw, 10);
            if (groupID !== null) payload.group_order.push(groupID);
            payload.sections.push({
                group_id: groupID,
                idp_ids: Array.prototype.slice.call(zone.querySelectorAll('.idp-chip')).map(function (c) {
                    return c.dataset.idpId;
                })
            });
        });

        saveBtn.disabled = true;
        fetch(root.dataset.arrangeUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'X-CSRF-Token': getCSRFToken()
            },
            body: JSON.stringify(payload)
        }).then(function (res) {
            return res.json().then(function (body) {
                return { ok: res.ok, body: body };
            });
        }).then(function (result) {
            if (result.ok) {
                showArrangeStatus('success', 'Arrangement saved.');
                if (hint) hint.textContent = 'All changes saved.';
            } else {
                saveBtn.disabled = false;
                showArrangeStatus('danger', result.body.error || 'Failed to save arrangement.');
            }
        }).catch(function () {
            saveBtn.disabled = false;
            showArrangeStatus('danger', 'Failed to save arrangement.');
        });
    });

    function showArrangeStatus(kind, message) {
        var box = document.getElementById('arrange-status');
        if (!box) return;
        box.className = 'alert alert-' + kind;
        box.textContent = message;
    }
}

/* ---- Provider Group Create/Edit/Delete Modals ---- */

// Fallback shown if the Bootstrap Icons stylesheet cannot be read (offline, or
// a CDN block). The full set is loaded from that stylesheet instead of being
// hardcoded, so the picker can never drift from the version actually linked.
var GROUP_ICON_FALLBACK = [
    'bi-building', 'bi-buildings', 'bi-bank', 'bi-house', 'bi-house-door', 'bi-shop',
    'bi-briefcase', 'bi-globe', 'bi-globe2', 'bi-geo-alt', 'bi-flag', 'bi-diagram-3',
    'bi-people', 'bi-person', 'bi-person-badge', 'bi-person-circle', 'bi-person-gear',
    'bi-person-vcard', 'bi-person-workspace', 'bi-people-fill', 'bi-person-lines-fill',
    'bi-shield', 'bi-shield-lock', 'bi-shield-check', 'bi-shield-shaded', 'bi-lock',
    'bi-unlock', 'bi-key', 'bi-fingerprint', 'bi-incognito', 'bi-patch-check',
    'bi-server', 'bi-hdd-network', 'bi-hdd-stack', 'bi-database', 'bi-cloud',
    'bi-cloud-check', 'bi-router', 'bi-ethernet', 'bi-cpu', 'bi-motherboard',
    'bi-pc-display', 'bi-laptop', 'bi-phone', 'bi-tablet', 'bi-display',
    'bi-window', 'bi-terminal', 'bi-code-slash', 'bi-braces', 'bi-bug',
    'bi-gear', 'bi-gear-wide-connected', 'bi-sliders', 'bi-tools', 'bi-wrench',
    'bi-folder', 'bi-folder2-open', 'bi-archive', 'bi-box', 'bi-boxes',
    'bi-journal', 'bi-journals', 'bi-book', 'bi-file-earmark-text', 'bi-clipboard-data',
    'bi-link-45deg', 'bi-box-arrow-up-right', 'bi-envelope', 'bi-chat-dots', 'bi-telephone',
    'bi-mortarboard', 'bi-hospital', 'bi-heart-pulse', 'bi-cart', 'bi-cash-coin',
    'bi-truck', 'bi-airplane', 'bi-lightning-charge', 'bi-star',
    'bi-bookmark', 'bi-tag', 'bi-tags', 'bi-grid', 'bi-grid-3x3-gap',
    'bi-list-ul', 'bi-collection', 'bi-stack', 'bi-puzzle', 'bi-three-dots'
];

// Icons are appended a page at a time as the grid is scrolled; drawing all
// ~2000 buttons up front is slow enough to be noticeable.
var GROUP_ICON_PAGE_SIZE = 120;

// loadBootstrapIconNames reads every icon class out of the linked Bootstrap
// Icons stylesheet. It is fetched rather than read from document.styleSheets
// because a CDN stylesheet is cross-origin and cssRules therefore throws.
function loadBootstrapIconNames() {
    var link = document.querySelector('link[href*="bootstrap-icons"]');
    if (!link) return Promise.resolve(null);

    return fetch(link.href).then(function (res) {
        return res.ok ? res.text() : null;
    }).then(function (css) {
        if (!css) return null;
        var names = [];
        var seen = Object.create(null);
        // The font declares one `.bi-name::before { content: "..." }` rule per icon.
        var re = /\.bi-([a-z0-9-]+)::?before/g;
        var m;
        while ((m = re.exec(css)) !== null) {
            if (seen[m[1]]) continue;
            seen[m[1]] = true;
            names.push('bi-' + m[1]);
        }
        return names.length ? names.sort() : null;
    }).catch(function () {
        return null;
    });
}

function initGroupIconPicker() {
    var input = document.getElementById('group-icon');
    var grid = document.getElementById('group-icon-grid');
    if (!input || !grid) return null;

    var preview = document.getElementById('group-icon-preview');
    var picker = document.getElementById('group-icon-picker');
    var browse = document.getElementById('group-icon-browse');
    var search = document.getElementById('group-icon-search');
    var status = document.getElementById('group-icon-status');

    var icons = GROUP_ICON_FALLBACK.slice().sort();
    var loaded = false;
    var matches = icons;
    var drawn = 0;

    function makeItem(name, selected) {
        var btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'icon-picker-item' + (name === selected ? ' selected' : '');
        btn.dataset.icon = name;
        btn.title = name;
        btn.setAttribute('role', 'option');
        btn.setAttribute('aria-label', name);
        var i = document.createElement('i');
        i.className = 'bi ' + name;
        btn.appendChild(i);
        return btn;
    }

    // Appends the next page and keeps going until the grid overflows, so a tall
    // window does not leave a short list with nothing left to scroll.
    function drawMore() {
        var selected = input.value.trim();
        while (drawn < matches.length) {
            var frag = document.createDocumentFragment();
            var end = Math.min(drawn + GROUP_ICON_PAGE_SIZE, matches.length);
            for (; drawn < end; drawn++) {
                frag.appendChild(makeItem(matches[drawn], selected));
            }
            grid.appendChild(frag);
            if (grid.scrollHeight > grid.clientHeight) break;
        }
        status.textContent = matches.length
            ? matches.length + (matches.length === 1 ? ' icon' : ' icons')
            : 'No icons match that search.';
    }

    function render() {
        var q = search.value.trim().toLowerCase();
        var selected = input.value.trim();
        matches = q ? icons.filter(function (n) { return n.indexOf(q) !== -1; }) : icons;
        // Pin the current icon to the front so it is visible without scrolling
        // to wherever it happens to sort.
        if (selected && matches.indexOf(selected) > 0) {
            matches = [selected].concat(matches.filter(function (n) { return n !== selected; }));
        }
        // Removing a hovered item would strand its tooltip on the body.
        grid.querySelectorAll('.icon-picker-item').forEach(function (btn) {
            var tip = bootstrap.Tooltip.getInstance(btn);
            if (tip) tip.dispose();
        });
        grid.replaceChildren();
        grid.scrollTop = 0;
        drawn = 0;
        drawMore();
    }

    // Delegated so items appended while scrolling get a tooltip for free, and
    // anchored to the body so the scrolling grid cannot clip it.
    new bootstrap.Tooltip(grid, {
        selector: '.icon-picker-item',
        container: 'body',
        delay: { show: 200, hide: 0 },
    });

    var shownTip = null;
    grid.addEventListener('inserted.bs.tooltip', function (e) { shownTip = e.target; });
    grid.addEventListener('hidden.bs.tooltip', function () { shownTip = null; });

    grid.addEventListener('scroll', function () {
        // Being anchored to the body, an open tooltip would otherwise ride its
        // item up and out of the grid.
        if (shownTip) {
            var tip = bootstrap.Tooltip.getInstance(shownTip);
            if (tip) tip.hide();
        }
        if (grid.scrollTop + grid.clientHeight >= grid.scrollHeight - 96) drawMore();
    });

    function syncPreview() {
        var name = input.value.trim();
        // Anything outside the bi-* namespace would be dropped server-side, so
        // show the placeholder rather than a misleading icon.
        var valid = /^bi-[a-z0-9-]+$/.test(name);
        preview.firstElementChild.className = 'bi ' + (valid ? name : 'bi-app');
        grid.querySelectorAll('.icon-picker-item').forEach(function (btn) {
            btn.classList.toggle('selected', btn.dataset.icon === name);
        });
    }

    function setOpen(open) {
        picker.classList.toggle('d-none', !open);
        browse.setAttribute('aria-expanded', open ? 'true' : 'false');
        if (!open) return;
        search.focus();
        if (loaded) return;
        loaded = true;
        loadBootstrapIconNames().then(function (names) {
            if (!names) return;
            icons = names;
            render();
        });
    }

    browse.addEventListener('click', function () {
        setOpen(picker.classList.contains('d-none'));
    });

    grid.addEventListener('click', function (e) {
        var btn = e.target.closest('.icon-picker-item');
        if (!btn) return;
        // Clicking the selected icon clears it, so an icon can be removed
        // without editing the text field.
        input.value = btn.classList.contains('selected') ? '' : btn.dataset.icon;
        syncPreview();
    });

    input.addEventListener('input', syncPreview);
    search.addEventListener('input', render);
    render();

    return { reset: function () { search.value = ''; render(); setOpen(false); syncPreview(); } };
}

function initGroupModals() {
    var modal = document.getElementById('group-modal');
    var iconPicker = initGroupIconPicker();

    if (modal) {
        var collapsible = document.getElementById('group-collapsible');
        var startCollapsed = document.getElementById('group-start-collapsed');
        var startWrap = document.getElementById('group-start-collapsed-wrap');

        // Starting collapsed is meaningless if users cannot expand the group.
        function syncStartCollapsed() {
            startWrap.classList.toggle('d-none', !collapsible.checked);
            if (!collapsible.checked) startCollapsed.checked = false;
        }
        collapsible.addEventListener('change', syncStartCollapsed);

        modal.addEventListener('show.bs.modal', function (e) {
            var trigger = e.relatedTarget;
            if (!trigger) return;
            var edit = trigger.dataset.groupMode === 'edit';
            var form = document.getElementById('group-form');

            document.getElementById('group-modal-title').textContent = edit ? 'Edit Group' : 'Add Group';
            form.action = edit ? '/admin/idp/groups/' + trigger.dataset.groupId : '/admin/idp/groups';
            document.getElementById('group-name').value = edit ? trigger.dataset.groupName : '';
            document.getElementById('group-description').value = edit ? trigger.dataset.groupDescription : '';
            document.getElementById('group-icon').value = edit ? trigger.dataset.groupIcon : '';
            collapsible.checked = edit && trigger.dataset.groupCollapsible === '1';
            startCollapsed.checked = edit && trigger.dataset.groupStartCollapsed === '1';
            syncStartCollapsed();
            if (iconPicker) iconPicker.reset();
        });
    }

    var deleteModal = document.getElementById('delete-group-modal');
    if (deleteModal) {
        deleteModal.addEventListener('show.bs.modal', function (e) {
            var trigger = e.relatedTarget;
            if (!trigger) return;
            document.getElementById('delete-group-form').action =
                '/admin/idp/groups/' + trigger.dataset.groupId + '/delete';
            document.getElementById('delete-group-name').textContent = trigger.dataset.groupName;
        });
    }
}
