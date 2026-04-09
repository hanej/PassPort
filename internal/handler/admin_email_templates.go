package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	htmltemplate "html/template"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"

	"github.com/hanej/passport/internal/audit"
	"github.com/hanej/passport/internal/auth"
	"github.com/hanej/passport/internal/db"
)

// templateVariables defines available template variables per template type.
var templateVariables = map[string][]string{
	"smtp_test":           {"Timestamp"},
	"forgot_password":     {"Username", "ProviderName", "TempPassword", "Timestamp"},
	"password_changed":    {"Username", "ProviderName", "Timestamp", "IPAddress"},
	"password_reset":      {"Username", "ProviderName", "Timestamp"},
	"password_expiration": {"Username", "ProviderName", "ExpirationDate", "DaysRemaining"},
	"account_locked":      {"Username", "ProviderName", "Timestamp", "Reason"},
	"account_unlocked":    {"Username", "ProviderName", "Timestamp"},
}

// templateNames maps template types to human-friendly names.
var templateNames = map[string]string{
	"smtp_test":           "SMTP Test Email",
	"forgot_password":     "Forgot Password",
	"password_changed":    "Password Changed",
	"password_reset":      "Password Reset",
	"password_expiration": "Password Expiration Warning (Default)",
	"account_locked":      "Account Locked",
	"account_unlocked":    "Account Unlocked",
}

// IsPasswordExpirationTemplate returns true for both the global and per-IDP expiration templates.
func IsPasswordExpirationTemplate(templateType string) bool {
	return templateType == "password_expiration" || strings.HasPrefix(templateType, "password_expiration:")
}

// defaultTemplates holds the default content for each template type (matching the SQL seed).
var defaultTemplates = map[string]struct {
	Subject  string
	BodyHTML string
}{
	"smtp_test": {
		Subject:  "PassPort Test Email",
		BodyHTML: `<h2>PassPort Test Email</h2><p>This is a test email from <strong>PassPort</strong>.</p><p>If you received this message, your SMTP configuration is working correctly.</p><p>Sent at: {{.Timestamp}}</p><p>— PassPort</p>`,
	},
	"forgot_password": {
		Subject:  "Password Reset Initiated",
		BodyHTML: `<h2>Password Reset</h2><p>Hello {{.Username}},</p><p>A password reset has been initiated for your <strong>{{.ProviderName}}</strong> account on {{.Timestamp}}.</p><p>Your temporary password is: <strong>{{.TempPassword}}</strong></p><p>Please use this temporary password to complete your password reset. It will only be valid for a single use.</p><p>If you did not request this reset, please contact your administrator immediately.</p><p>— PassPort</p>`,
	},
	"password_changed": {
		Subject:  "Your password has been changed",
		BodyHTML: `<h2>Password Changed</h2><p>Hello {{.Username}},</p><p>Your password for <strong>{{.ProviderName}}</strong> was successfully changed on {{.Timestamp}}.</p><p>If you did not make this change, please contact your administrator immediately.</p><p>— PassPort</p>`,
	},
	"password_reset": {
		Subject:  "Your password has been reset",
		BodyHTML: `<h2>Password Reset</h2><p>Hello {{.Username}},</p><p>Your password for <strong>{{.ProviderName}}</strong> was reset on {{.Timestamp}}.</p><p>If you did not request this reset, please contact your administrator immediately.</p><p>— PassPort</p>`,
	},
	"password_expiration": {
		Subject:  "Your password is expiring soon",
		BodyHTML: `<h2>Password Expiration Notice</h2><p>Hello {{.Username}},</p><p>Your password for <strong>{{.ProviderName}}</strong> will expire on <strong>{{.ExpirationDate}}</strong> ({{.DaysRemaining}} days remaining).</p><p>Please change your password before it expires to avoid service interruption.</p><p>— PassPort</p>`,
	},
	"account_locked": {
		Subject:  "Your account has been locked",
		BodyHTML: `<h2>Account Locked</h2><p>Hello {{.Username}},</p><p>Your <strong>{{.ProviderName}}</strong> account was locked on {{.Timestamp}}.</p><p>Reason: {{.Reason}}</p><p>Please contact your administrator for assistance.</p><p>— PassPort</p>`,
	},
	"account_unlocked": {
		Subject:  "Your account has been unlocked",
		BodyHTML: `<h2>Account Unlocked</h2><p>Hello {{.Username}},</p><p>Your <strong>{{.ProviderName}}</strong> account has been unlocked as of {{.Timestamp}}.</p><p>You may now log in normally.</p><p>— PassPort</p>`,
	},
}

// AdminEmailTemplatesHandler handles email template management in the admin UI.
type AdminEmailTemplatesHandler struct {
	store    db.Store
	renderer *Renderer
	audit    *audit.Logger
	sessions *auth.SessionManager
	logger   *slog.Logger
}

// NewAdminEmailTemplatesHandler creates a new AdminEmailTemplatesHandler.
func NewAdminEmailTemplatesHandler(
	store db.Store,
	renderer *Renderer,
	sessions *auth.SessionManager,
	auditLogger *audit.Logger,
	logger *slog.Logger,
) *AdminEmailTemplatesHandler {
	return &AdminEmailTemplatesHandler{
		store:    store,
		renderer: renderer,
		sessions: sessions,
		audit:    auditLogger,
		logger:   logger,
	}
}

// List renders the email templates list page.
// GET /admin/email-templates
func (h *AdminEmailTemplatesHandler) List(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("List email templates called")

	sess := auth.SessionFromContext(r.Context())

	templates, err := h.store.ListEmailTemplates(r.Context())
	if err != nil {
		h.logger.Error("failed to list email templates", "error", err)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Failed to load email templates")
		return
	}

	// Build display data with friendly names.
	type templateRow struct {
		TemplateType string
		FriendlyName string
		Subject      string
		UpdatedAt    time.Time
	}
	var rows []templateRow
	for _, t := range templates {
		name := templateNames[t.TemplateType]
		if name == "" && IsPasswordExpirationTemplate(t.TemplateType) {
			idpID := strings.TrimPrefix(t.TemplateType, "password_expiration:")
			name = "Password Expiration Warning — " + idpID
		}
		if name == "" {
			name = t.TemplateType
		}
		rows = append(rows, templateRow{
			TemplateType: t.TemplateType,
			FriendlyName: name,
			Subject:      t.Subject,
			UpdatedAt:    t.UpdatedAt,
		})
	}

	h.logger.Debug("email templates loaded", "count", len(rows))

	h.renderer.Render(w, r, "admin_email_templates.html", PageData{
		Title:     "Email Templates",
		Session:   sess,
		CSRFField: csrf.TemplateField(r),
		Data: map[string]any{
			"Templates":  rows,
			"ActivePage": "email_templates",
		},
	})
}

// Edit renders the email template edit form.
// GET /admin/email-templates/{type}/edit
func (h *AdminEmailTemplatesHandler) Edit(w http.ResponseWriter, r *http.Request) {
	templateType := chi.URLParam(r, "type")
	h.logger.Debug("Edit email template called", "type", templateType)

	sess := auth.SessionFromContext(r.Context())

	// Validate type: either in the global list or a per-IDP password_expiration template.
	vars, ok := templateVariables[templateType]
	friendlyName := templateNames[templateType]
	if !ok && IsPasswordExpirationTemplate(templateType) {
		vars = templateVariables["password_expiration"]
		idpID := strings.TrimPrefix(templateType, "password_expiration:")
		friendlyName = "Password Expiration Warning — " + idpID
	} else if !ok {
		h.logger.Debug("invalid template type", "type", templateType)
		h.renderer.RenderError(w, r, http.StatusNotFound, "Template not found")
		return
	}

	tmpl, err := h.store.GetEmailTemplate(r.Context(), templateType)
	if err != nil {
		// For per-IDP templates that don't exist yet, start with the global default.
		if IsPasswordExpirationTemplate(templateType) && templateType != "password_expiration" {
			globalTmpl, globalErr := h.store.GetEmailTemplate(r.Context(), "password_expiration")
			if globalErr == nil {
				tmpl = globalTmpl
				tmpl.TemplateType = templateType
			}
		}
		if tmpl == nil {
			h.logger.Error("failed to get email template", "type", templateType, "error", err)
			h.renderer.RenderError(w, r, http.StatusInternalServerError, "Failed to load template")
			return
		}
	}

	h.logger.Debug("email template loaded for editing",
		"type", templateType,
		"subject", tmpl.Subject,
	)

	h.renderer.Render(w, r, "admin_email_template_form.html", PageData{
		Title:     "Edit " + friendlyName,
		Session:   sess,
		CSRFField: csrf.TemplateField(r),
		Data: map[string]any{
			"Template":     tmpl,
			"Variables":    vars,
			"FriendlyName": friendlyName,
			"TemplateType": templateType,
			"ActivePage":   "email_templates",
		},
	})
}

// Save processes the email template edit form.
// POST /admin/email-templates/{type}
func (h *AdminEmailTemplatesHandler) Save(w http.ResponseWriter, r *http.Request) {
	templateType := chi.URLParam(r, "type")
	h.logger.Debug("Save email template called", "type", templateType)

	sess := auth.SessionFromContext(r.Context())

	// Validate type: either in the global list or a per-IDP password_expiration template.
	if _, ok := templateVariables[templateType]; !ok && !IsPasswordExpirationTemplate(templateType) {
		h.logger.Debug("invalid template type on save", "type", templateType)
		h.renderer.RenderError(w, r, http.StatusNotFound, "Template not found")
		return
	}

	if err := r.ParseForm(); err != nil {
		h.renderer.RenderError(w, r, http.StatusBadRequest, "Invalid form data")
		return
	}

	subject := r.FormValue("subject")
	bodyHTML := r.FormValue("body_html")

	tmpl := &db.EmailTemplate{
		TemplateType: templateType,
		Subject:      subject,
		BodyHTML:     bodyHTML,
	}

	if err := h.store.SaveEmailTemplate(r.Context(), tmpl); err != nil {
		h.logger.Error("failed to save email template", "type", templateType, "error", err)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Failed to save template")
		return
	}

	h.logger.Debug("email template saved",
		"type", templateType,
		"subject", subject,
	)

	h.audit.Log(r.Context(), &db.AuditEntry{
		Timestamp: time.Now().UTC(),
		Username:  sess.Username,
		SourceIP:  r.RemoteAddr,
		Action:    audit.ActionEmailTemplateUpdate,
		Result:    audit.ResultSuccess,
		Details:   fmt.Sprintf("Updated email template: %s", templateType),
	})

	h.sessions.SetFlash(w, r, "success", "Email template saved successfully")
	http.Redirect(w, r, "/admin/email-templates", http.StatusFound)
}

// Delete removes a per-IDP email template. Global templates cannot be deleted.
// POST /admin/email-templates/{type}/delete
func (h *AdminEmailTemplatesHandler) Delete(w http.ResponseWriter, r *http.Request) {
	templateType := chi.URLParam(r, "type")
	h.logger.Debug("Delete email template called", "type", templateType)

	sess := auth.SessionFromContext(r.Context())

	// Only per-IDP templates can be deleted.
	if !strings.Contains(templateType, ":") {
		h.sessions.SetFlash(w, r, "error", "Global templates cannot be deleted — use Reset to Default instead")
		http.Redirect(w, r, "/admin/email-templates", http.StatusFound)
		return
	}

	if err := h.store.DeleteEmailTemplate(r.Context(), templateType); err != nil {
		h.logger.Error("failed to delete email template", "type", templateType, "error", err)
		h.sessions.SetFlash(w, r, "error", "Failed to delete template")
		http.Redirect(w, r, "/admin/email-templates", http.StatusFound)
		return
	}

	h.audit.Log(r.Context(), &db.AuditEntry{
		Timestamp: time.Now().UTC(),
		Username:  sess.Username,
		SourceIP:  r.RemoteAddr,
		Action:    audit.ActionEmailTemplateReset,
		Result:    audit.ResultSuccess,
		Details:   fmt.Sprintf("Deleted per-IDP email template: %s", templateType),
	})

	h.sessions.SetFlash(w, r, "success", "Template deleted — the global default will be used instead")
	http.Redirect(w, r, "/admin/email-templates", http.StatusFound)
}

// previewRequest is the JSON body for the preview endpoint.
type previewRequest struct {
	TemplateType string `json:"template_type"`
	BodyHTML     string `json:"body_html"`
	Subject      string `json:"subject"`
}

// Preview renders an email template with sample data and returns JSON.
// POST /admin/email-templates/preview
func (h *AdminEmailTemplatesHandler) Preview(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("Preview email template called")

	var req previewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Debug("invalid preview request body", "error", err)
		h.renderer.JSON(w, http.StatusBadRequest, map[string]string{
			"error": "Invalid request body",
		})
		return
	}

	h.logger.Debug("preview request",
		"type", req.TemplateType,
		"subject_len", len(req.Subject),
		"body_len", len(req.BodyHTML),
	)

	// Build sample data based on template type.
	sampleData := map[string]string{
		"Username":       "John Doe",
		"ProviderName":   "Corporate AD",
		"Timestamp":      time.Now().Local().Format("Jan 2, 2006 3:04 PM MST"),
		"IPAddress":      "192.168.1.100",
		"ExpirationDate": time.Now().Local().Add(7 * 24 * time.Hour).Format("Jan 2, 2006"),
		"DaysRemaining":  "7",
		"Reason":         "Too many failed login attempts",
	}

	renderedHTML, err := executeTemplate(req.BodyHTML, sampleData)
	if err != nil {
		h.logger.Debug("template execution failed for body", "error", err)
		h.renderer.JSON(w, http.StatusOK, map[string]any{
			"error": fmt.Sprintf("Template error: %v", err),
		})
		return
	}

	renderedSubject, err := executeTemplate(req.Subject, sampleData)
	if err != nil {
		h.logger.Debug("template execution failed for subject", "error", err)
		h.renderer.JSON(w, http.StatusOK, map[string]any{
			"error": fmt.Sprintf("Subject template error: %v", err),
		})
		return
	}

	h.logger.Debug("preview rendered successfully")

	h.renderer.JSON(w, http.StatusOK, map[string]any{
		"rendered_html":    renderedHTML,
		"rendered_subject": renderedSubject,
	})
}

// executeTemplate parses and executes a Go template string with the given data.
// It recovers from panics caused by malformed templates.
func executeTemplate(tmplStr string, data any) (result string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("template panic: %v", r)
		}
	}()

	t, err := htmltemplate.New("preview").Parse(tmplStr)
	if err != nil {
		return "", fmt.Errorf("parse error: %w", err)
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("execute error: %w", err)
	}
	return buf.String(), nil
}

// ResetDefault resets an email template to its hardcoded default.
// POST /admin/email-templates/{type}/reset
func (h *AdminEmailTemplatesHandler) ResetDefault(w http.ResponseWriter, r *http.Request) {
	templateType := chi.URLParam(r, "type")
	h.logger.Debug("ResetDefault email template called", "type", templateType)

	sess := auth.SessionFromContext(r.Context())

	def, ok := defaultTemplates[templateType]
	if !ok {
		h.logger.Debug("invalid template type on reset", "type", templateType)
		h.renderer.RenderError(w, r, http.StatusNotFound, "Template not found")
		return
	}

	tmpl := &db.EmailTemplate{
		TemplateType: templateType,
		Subject:      def.Subject,
		BodyHTML:     def.BodyHTML,
	}

	if err := h.store.SaveEmailTemplate(r.Context(), tmpl); err != nil {
		h.logger.Error("failed to reset email template", "type", templateType, "error", err)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Failed to reset template")
		return
	}

	h.logger.Debug("email template reset to default", "type", templateType)

	h.audit.Log(r.Context(), &db.AuditEntry{
		Timestamp: time.Now().UTC(),
		Username:  sess.Username,
		SourceIP:  r.RemoteAddr,
		Action:    audit.ActionEmailTemplateReset,
		Result:    audit.ResultSuccess,
		Details:   fmt.Sprintf("Reset email template to default: %s", templateType),
	})

	h.sessions.SetFlash(w, r, "success", "Email template reset to default")
	http.Redirect(w, r, "/admin/email-templates/"+templateType+"/edit", http.StatusFound)
}
