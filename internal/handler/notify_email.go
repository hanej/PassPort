package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/hanej/passport/internal/crypto"
	"github.com/hanej/passport/internal/db"
	"github.com/hanej/passport/internal/email"
	"github.com/hanej/passport/internal/idp"
)

// resolveNotificationEmailByDN looks up a user's notification email address
// from the IDP directory using an already-known DN. The IDP's configured
// notification email attribute is used (defaults to "mail").
func resolveNotificationEmailByDN(ctx context.Context, store db.Store, provider idp.Provider, idpID, userDN string) (string, error) {
	idpRecord, err := store.GetIDP(ctx, idpID)
	if err != nil {
		return "", fmt.Errorf("loading IDP record: %w", err)
	}

	var idpCfg idp.Config
	if idpRecord.ConfigJSON != "" {
		if err := json.Unmarshal([]byte(idpRecord.ConfigJSON), &idpCfg); err != nil {
			return "", fmt.Errorf("parsing IDP config: %w", err)
		}
	}

	emailAttr := idpCfg.NotificationEmailAttr
	if emailAttr == "" {
		emailAttr = "mail"
	}

	userEmail, err := provider.GetUserAttribute(ctx, userDN, emailAttr)
	if err != nil {
		return "", fmt.Errorf("getting email attribute %q for %q: %w", emailAttr, userDN, err)
	}
	return userEmail, nil
}

// resolveNotificationEmailByUsername resolves a user's DN via the directory
// and then looks up their notification email address.
func resolveNotificationEmailByUsername(ctx context.Context, store db.Store, registry *idp.Registry, idpID, username string) (string, error) {
	provider, ok := registry.Get(idpID)
	if !ok {
		return "", fmt.Errorf("IDP %s not found in registry", idpID)
	}

	userDN, err := provider.SearchUser(ctx, "uid", username)
	if err != nil {
		userDN, err = provider.SearchUser(ctx, "sAMAccountName", username)
	}
	if err != nil {
		return "", fmt.Errorf("user %q not found in directory: %w", username, err)
	}

	return resolveNotificationEmailByDN(ctx, store, provider, idpID, userDN)
}

// sendPasswordEventEmail renders and sends a templated notification email
// (e.g. "password_changed", "password_reset") for a password-related event.
// It checks for an IDP-specific template first ("<type>:<idpID>"), falling
// back to the global template for that type.
//
// This never returns an error to the caller: by the time it's invoked, the
// password change/reset has already succeeded against the directory, so a
// notification failure must not block the response. All failures (and the
// eventual success) are logged so operators can see what happened.
func sendPasswordEventEmail(
	ctx context.Context,
	store db.Store,
	cryptoSvc *crypto.Service,
	logger *slog.Logger,
	templateType, idpID, providerName, username, userEmail, sourceIP string,
) {
	if userEmail == "" {
		logger.Warn("skipping notification email: user has no email address on file",
			"template", templateType, "idp_id", idpID, "username", username)
		return
	}

	smtpRecord, err := store.GetSMTPConfig(ctx)
	if err != nil || smtpRecord == nil {
		logger.Warn("skipping notification email: SMTP not configured",
			"template", templateType, "idp_id", idpID, "username", username)
		return
	}

	emailCfg, err := buildEmailConfigFromRecord(smtpRecord, cryptoSvc)
	if err != nil {
		logger.Warn("skipping notification email: SMTP not usable",
			"template", templateType, "idp_id", idpID, "username", username, "error", err)
		return
	}

	tmpl, err := store.GetEmailTemplate(ctx, templateType+":"+idpID)
	if err != nil || tmpl == nil {
		tmpl, err = store.GetEmailTemplate(ctx, templateType)
		if err != nil || tmpl == nil {
			logger.Warn("skipping notification email: template not found",
				"template", templateType, "idp_id", idpID, "username", username)
			return
		}
	}

	data := map[string]string{
		"Username":     username,
		"ProviderName": providerName,
		"Timestamp":    time.Now().Local().Format("Jan 2, 2006 3:04 PM MST"),
		"IPAddress":    sourceIP,
	}

	subject, err := executeTemplate(tmpl.Subject, data)
	if err != nil {
		logger.Warn("failed to render notification email subject",
			"template", templateType, "idp_id", idpID, "username", username, "error", err)
		return
	}
	body, err := executeTemplate(tmpl.BodyHTML, data)
	if err != nil {
		logger.Warn("failed to render notification email body",
			"template", templateType, "idp_id", idpID, "username", username, "error", err)
		return
	}

	if err := email.SendHTML(emailCfg, userEmail, subject, body); err != nil {
		logger.Warn("failed to send notification email",
			"template", templateType, "idp_id", idpID, "username", username, "to", userEmail, "error", err)
		return
	}

	logger.Info("notification email sent",
		"template", templateType, "idp_id", idpID, "username", username, "to", userEmail)
}
