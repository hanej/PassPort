package handler

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	htmltemplate "html/template"
	"io"
	"log/slog"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"time"

	"github.com/hanej/passport/internal/audit"
	"github.com/hanej/passport/internal/auth"
	"github.com/hanej/passport/internal/crypto"
	"github.com/hanej/passport/internal/db"
)

// SMTPConfigFields holds the non-sensitive SMTP configuration fields.
type SMTPConfigFields struct {
	Host          string `json:"host"`
	Port          string `json:"port"`
	FromAddress   string `json:"from_address"`
	FromName      string `json:"from_name"`
	UseTLS        bool   `json:"use_tls"`
	UseStartTLS   bool   `json:"use_starttls"`
	TLSSkipVerify bool   `json:"tls_skip_verify"`
	Enabled       bool   `json:"enabled"`
}

// SMTPSecrets holds the sensitive SMTP configuration fields.
type SMTPSecrets struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// AdminSMTPHandler handles SMTP configuration in the admin UI.
type AdminSMTPHandler struct {
	store    db.Store
	crypto   *crypto.Service
	renderer *Renderer
	audit    *audit.Logger
	logger   *slog.Logger
}

// NewAdminSMTPHandler creates a new AdminSMTPHandler.
func NewAdminSMTPHandler(
	store db.Store,
	cryptoSvc *crypto.Service,
	renderer *Renderer,
	auditLogger *audit.Logger,
	logger *slog.Logger,
) *AdminSMTPHandler {
	return &AdminSMTPHandler{
		store:    store,
		crypto:   cryptoSvc,
		renderer: renderer,
		audit:    auditLogger,
		logger:   logger,
	}
}

// Show renders the SMTP configuration page.
// GET /admin/smtp
func (h *AdminSMTPHandler) Show(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("Show SMTP config called")

	sess := auth.SessionFromContext(r.Context())

	var configFields SMTPConfigFields
	var secrets SMTPSecrets

	cfg, err := h.store.GetSMTPConfig(r.Context())
	if err != nil {
		h.logger.Debug("no SMTP config found, showing empty form", "error", err)
	} else if cfg != nil {
		if cfg.ConfigJSON != "" {
			if err := json.Unmarshal([]byte(cfg.ConfigJSON), &configFields); err != nil {
				h.logger.Error("failed to unmarshal SMTP config", "error", err)
			}
		}
		if len(cfg.SecretBlob) > 0 {
			plaintext, err := h.crypto.Decrypt(cfg.SecretBlob)
			if err != nil {
				h.logger.Error("failed to decrypt SMTP secrets", "error", err)
			} else {
				if err := json.Unmarshal(plaintext, &secrets); err != nil {
					h.logger.Error("failed to unmarshal SMTP secrets", "error", err)
				}
			}
		}
	}

	h.logger.Debug("SMTP config loaded",
		"host", configFields.Host,
		"enabled", configFields.Enabled,
	)

	h.renderer.Render(w, r, "admin_smtp.html", PageData{
		Title:   "SMTP Configuration",
		Session: sess,
		Data: map[string]any{
			"Config":     configFields,
			"Secrets":    secrets,
			"ActivePage": "smtp",
		},
	})
}

// Save processes the SMTP configuration form.
// POST /admin/smtp
func (h *AdminSMTPHandler) Save(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("Save SMTP config called")

	sess := auth.SessionFromContext(r.Context())

	if err := r.ParseForm(); err != nil {
		h.renderer.RenderError(w, r, http.StatusBadRequest, "Invalid form data")
		return
	}

	configFields := SMTPConfigFields{
		Host:          r.FormValue("host"),
		Port:          r.FormValue("port"),
		FromAddress:   r.FormValue("from_address"),
		FromName:      r.FormValue("from_name"),
		UseTLS:        r.FormValue("use_tls") == "on",
		UseStartTLS:   r.FormValue("use_starttls") == "on",
		TLSSkipVerify: r.FormValue("tls_skip_verify") == "on",
		Enabled:       r.FormValue("enabled") == "on",
	}

	configJSON, err := json.Marshal(configFields)
	if err != nil {
		h.logger.Error("failed to marshal SMTP config", "error", err)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Internal server error")
		return
	}

	secrets := SMTPSecrets{
		Username: r.FormValue("username"),
		Password: r.FormValue("password"),
	}

	secretsJSON, err := json.Marshal(secrets)
	if err != nil {
		h.logger.Error("failed to marshal SMTP secrets", "error", err)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Internal server error")
		return
	}

	secretBlob, err := h.crypto.Encrypt(secretsJSON)
	if err != nil {
		h.logger.Error("failed to encrypt SMTP secrets", "error", err)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Internal server error")
		return
	}

	cfg := &db.SMTPConfig{
		ConfigJSON: string(configJSON),
		SecretBlob: secretBlob,
		UpdatedAt:  time.Now().UTC(),
	}

	if err := h.store.SaveSMTPConfig(r.Context(), cfg); err != nil {
		h.logger.Error("failed to save SMTP config", "error", err)
		h.renderer.Render(w, r, "admin_smtp.html", PageData{
			Title:   "SMTP Configuration",
			Session: sess,
			Flash:   map[string]string{"category": "error", "message": "Failed to save SMTP configuration"},
			Data: map[string]any{
				"Config":  configFields,
				"Secrets": secrets,
			},
		})
		return
	}

	h.logger.Debug("SMTP config saved successfully",
		"host", configFields.Host,
		"enabled", configFields.Enabled,
	)

	h.audit.Log(r.Context(), &db.AuditEntry{
		Timestamp: time.Now().UTC(),
		Username:  sess.Username,
		SourceIP:  r.RemoteAddr,
		Action:    audit.ActionSMTPUpdate,
		Result:    audit.ResultSuccess,
		Details:   fmt.Sprintf("Updated SMTP config (host=%s, enabled=%v)", configFields.Host, configFields.Enabled),
	})

	h.renderer.Render(w, r, "admin_smtp.html", PageData{
		Title:   "SMTP Configuration",
		Session: sess,
		Flash:   map[string]string{"category": "success", "message": "SMTP configuration saved successfully"},
		Data: map[string]any{
			"Config":  configFields,
			"Secrets": secrets,
		},
	})
}

// TestEmail sends a test email via the saved SMTP configuration. Returns JSON.
// POST /admin/smtp/test
func (h *AdminSMTPHandler) TestEmail(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("TestEmail called")

	sess := auth.SessionFromContext(r.Context())

	parsedTo, err := mail.ParseAddress(r.FormValue("to"))
	if err != nil {
		h.renderer.JSON(w, http.StatusBadRequest, map[string]string{
			"status":  "error",
			"message": "A valid recipient email address is required",
		})
		return
	}
	toAddr := parsedTo.Address

	cfg, err := h.store.GetSMTPConfig(r.Context())
	if err != nil || cfg == nil {
		h.renderer.JSON(w, http.StatusBadRequest, map[string]string{
			"status":  "error",
			"message": "No SMTP configuration found. Please save the configuration first.",
		})
		return
	}

	var configFields SMTPConfigFields
	if err := json.Unmarshal([]byte(cfg.ConfigJSON), &configFields); err != nil {
		h.renderer.JSON(w, http.StatusInternalServerError, map[string]string{
			"status":  "error",
			"message": "Invalid SMTP configuration",
		})
		return
	}

	if !configFields.Enabled {
		h.renderer.JSON(w, http.StatusBadRequest, map[string]string{
			"status":  "error",
			"message": "SMTP is not enabled",
		})
		return
	}

	if configFields.Host == "" || configFields.Port == "" {
		h.renderer.JSON(w, http.StatusBadRequest, map[string]string{
			"status":  "error",
			"message": "SMTP host and port are required",
		})
		return
	}

	var secrets SMTPSecrets
	if len(cfg.SecretBlob) > 0 {
		plaintext, err := h.crypto.Decrypt(cfg.SecretBlob)
		if err != nil {
			h.renderer.JSON(w, http.StatusInternalServerError, map[string]string{
				"status":  "error",
				"message": "Failed to decrypt SMTP credentials",
			})
			return
		}
		if err := json.Unmarshal(plaintext, &secrets); err != nil {
			h.renderer.JSON(w, http.StatusInternalServerError, map[string]string{
				"status":  "error",
				"message": "Invalid SMTP credentials",
			})
			return
		}
	}

	// Load and render the smtp_test email template.
	tmpl, err := h.store.GetEmailTemplate(r.Context(), "smtp_test")
	var subject, htmlBody string
	if err != nil || tmpl == nil {
		// Fallback if template not found.
		subject = "PassPort Test Email"
		htmlBody = "<p>This is a test email from PassPort. Your SMTP configuration is working correctly.</p><p>Sent at: " + time.Now().Local().Format("Jan 2, 2006 3:04 PM MST") + "</p>"
	} else {
		data := map[string]string{
			"Timestamp": time.Now().Local().Format("Jan 2, 2006 3:04 PM MST"),
		}
		subject = tmpl.Subject
		if rendered, err := renderSimpleTemplate(tmpl.Subject, data); err == nil {
			subject = rendered
		}
		if rendered, err := renderSimpleTemplate(tmpl.BodyHTML, data); err == nil {
			htmlBody = rendered
		} else {
			htmlBody = tmpl.BodyHTML
		}
	}

	h.logger.Debug("sending test email",
		"to", toAddr,
		"host", configFields.Host,
		"port", configFields.Port,
		"from", configFields.FromAddress,
	)

	if err := sendEmail(configFields, secrets, toAddr, subject, htmlBody); err != nil {
		h.logger.Warn("test email failed", "error", err, "to", toAddr)
		h.audit.Log(r.Context(), &db.AuditEntry{
			Timestamp: time.Now().UTC(),
			Username:  sess.Username,
			SourceIP:  r.RemoteAddr,
			Action:    audit.ActionSMTPTest,
			Result:    audit.ResultFailure,
			Details:   fmt.Sprintf("Test email to %s failed: %v", toAddr, err),
		})
		h.renderer.JSON(w, http.StatusOK, map[string]string{
			"status":  "error",
			"message": "Failed to send: " + err.Error(),
		})
		return
	}

	h.logger.Info("test email sent", "to", toAddr)
	h.audit.Log(r.Context(), &db.AuditEntry{
		Timestamp: time.Now().UTC(),
		Username:  sess.Username,
		SourceIP:  r.RemoteAddr,
		Action:    audit.ActionSMTPTest,
		Result:    audit.ResultSuccess,
		Details:   fmt.Sprintf("Test email sent to %s", toAddr),
	})

	h.renderer.JSON(w, http.StatusOK, map[string]string{
		"status":  "success",
		"message": "Test email sent to " + toAddr,
	})
}

// buildMIMEMessage constructs a properly encoded MIME email message.
// Headers use net/mail address formatting and RFC 2047 Q-encoding for the
// subject. The HTML body is encoded as quoted-printable per RFC 2045.
func buildMIMEMessage(fromName, fromAddr, to, subject, htmlBody string) ([]byte, error) {
	from := mail.Address{Name: fromName, Address: fromAddr}
	recipient := mail.Address{Address: to}

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "From: %s\r\n", from.String())
	fmt.Fprintf(&buf, "To: %s\r\n", recipient.String())
	fmt.Fprintf(&buf, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", subject))
	fmt.Fprintf(&buf, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	buf.WriteString("MIME-Version: 1.0\r\n")
	buf.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	buf.WriteString("Content-Transfer-Encoding: quoted-printable\r\n")
	buf.WriteString("\r\n")

	qw := quotedprintable.NewWriter(&buf)
	if _, err := io.WriteString(qw, htmlBody); err != nil {
		return nil, err
	}
	if err := qw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// sendEmail sends an HTML email using the provided SMTP configuration.
func sendEmail(cfg SMTPConfigFields, secrets SMTPSecrets, to, subject, htmlBody string) error {
	addr := net.JoinHostPort(cfg.Host, cfg.Port)

	fromName := cfg.FromName
	if fromName == "" {
		fromName = "PassPort"
	}

	msg, err := buildMIMEMessage(fromName, cfg.FromAddress, to, subject, htmlBody)
	if err != nil {
		return fmt.Errorf("building message: %w", err)
	}

	// Set up authentication if credentials are provided.
	var auth smtp.Auth
	if secrets.Username != "" && secrets.Password != "" {
		auth = smtp.PlainAuth("", secrets.Username, secrets.Password, cfg.Host)
	}

	if cfg.UseTLS {
		// Direct TLS connection (port 465 typically).
		return sendEmailTLS(addr, cfg.Host, cfg.TLSSkipVerify, auth, cfg.FromAddress, to, []byte(msg))
	}

	// Plain SMTP or STARTTLS — connect plaintext first.
	client, err := smtp.Dial(addr)
	if err != nil {
		return fmt.Errorf("SMTP dial: %w", err)
	}
	defer func() { _ = client.Close() }()

	// Upgrade with STARTTLS if configured, or if the server advertises it.
	if cfg.UseStartTLS {
		tlsConfig := &tls.Config{ServerName: cfg.Host, InsecureSkipVerify: cfg.TLSSkipVerify}
		if err := client.StartTLS(tlsConfig); err != nil {
			return fmt.Errorf("STARTTLS: %w", err)
		}
	}

	return smtpSend(client, auth, cfg.FromAddress, to, []byte(msg))
}

// sendEmailTLS sends via a direct TLS connection (SMTPS, typically port 465).
func sendEmailTLS(addr, host string, skipVerify bool, auth smtp.Auth, from, to string, msg []byte) error {
	tlsConfig := &tls.Config{ServerName: host, InsecureSkipVerify: skipVerify}
	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("TLS dial: %w", err)
	}

	client, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("SMTP client: %w", err)
	}
	defer func() { _ = client.Close() }()

	return smtpSend(client, auth, from, to, msg)
}

// smtpSend performs the AUTH, MAIL FROM, RCPT TO, DATA sequence on an smtp.Client.
func smtpSend(client *smtp.Client, auth smtp.Auth, from, to string, msg []byte) error {
	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("AUTH: %w", err)
		}
	}
	if err := client.Mail(from); err != nil {
		return fmt.Errorf("MAIL FROM: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("RCPT TO: %w", err)
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("DATA: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("writing message: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("closing message: %w", err)
	}
	return client.Quit()
}

// renderSimpleTemplate renders a Go html/template string with the given data.
func renderSimpleTemplate(tmplStr string, data any) (string, error) {
	t, err := htmltemplate.New("email").Parse(tmplStr)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}
