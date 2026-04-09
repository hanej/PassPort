package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// ListEmailTemplates returns all email templates ordered by template_type.
func (d *DB) ListEmailTemplates(ctx context.Context) ([]EmailTemplate, error) {
	rows, err := d.reader.QueryContext(ctx, `
		SELECT id, template_type, subject, body_html, updated_at
		FROM email_templates ORDER BY template_type`)
	if err != nil {
		return nil, fmt.Errorf("list email templates: %w", err)
	}
	defer rows.Close()

	var templates []EmailTemplate
	for rows.Next() {
		var t EmailTemplate
		var updatedAt string
		if err := rows.Scan(&t.ID, &t.TemplateType, &t.Subject, &t.BodyHTML, &updatedAt); err != nil {
			return nil, fmt.Errorf("scan email template: %w", err)
		}
		var parseErr error
		if t.UpdatedAt, parseErr = time.Parse(tsLayout, updatedAt); parseErr != nil {
			return nil, fmt.Errorf("parse email template updated_at: %w", parseErr)
		}
		templates = append(templates, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate email templates: %w", err)
	}
	return templates, nil
}

// GetEmailTemplate retrieves an email template by template_type.
// Returns ErrNotFound if no matching row exists.
func (d *DB) GetEmailTemplate(ctx context.Context, templateType string) (*EmailTemplate, error) {
	row := d.reader.QueryRowContext(ctx, `
		SELECT id, template_type, subject, body_html, updated_at
		FROM email_templates WHERE template_type = ?`, templateType)

	var t EmailTemplate
	var updatedAt string
	err := row.Scan(&t.ID, &t.TemplateType, &t.Subject, &t.BodyHTML, &updatedAt)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get email template: %w", err)
	}
	var parseErr error
	if t.UpdatedAt, parseErr = time.Parse(tsLayout, updatedAt); parseErr != nil {
		return nil, fmt.Errorf("parse email template updated_at: %w", parseErr)
	}
	return &t, nil
}

// SaveEmailTemplate inserts or replaces an email template, setting updated_at to now.
func (d *DB) SaveEmailTemplate(ctx context.Context, t *EmailTemplate) error {
	_, err := d.writer.ExecContext(ctx, `
		INSERT INTO email_templates (template_type, subject, body_html, updated_at)
		VALUES (?, ?, ?, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
		ON CONFLICT(template_type) DO UPDATE SET
			subject    = excluded.subject,
			body_html  = excluded.body_html,
			updated_at = excluded.updated_at`,
		t.TemplateType, t.Subject, t.BodyHTML)
	if err != nil {
		return fmt.Errorf("save email template: %w", err)
	}
	return nil
}

// DeleteEmailTemplate removes an email template by type.
func (d *DB) DeleteEmailTemplate(ctx context.Context, templateType string) error {
	result, err := d.writer.ExecContext(ctx,
		`DELETE FROM email_templates WHERE template_type = ?`, templateType)
	if err != nil {
		return fmt.Errorf("delete email template: %w", err)
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
