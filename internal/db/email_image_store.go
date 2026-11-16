package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

const emailImageColumns = `id, name, filename, content_type, size_bytes, width, height, created_at`

type rowScanner interface {
	Scan(dest ...any) error
}

func scanEmailImage(s rowScanner) (*EmailImage, error) {
	var img EmailImage
	var createdAt string
	if err := s.Scan(&img.ID, &img.Name, &img.Filename, &img.ContentType,
		&img.SizeBytes, &img.Width, &img.Height, &createdAt); err != nil {
		return nil, err
	}
	t, err := time.Parse(tsLayout, createdAt)
	if err != nil {
		return nil, fmt.Errorf("parse email image created_at: %w", err)
	}
	img.CreatedAt = t
	return &img, nil
}

// ListEmailImages returns all library images, newest first.
func (d *DB) ListEmailImages(ctx context.Context) ([]EmailImage, error) {
	rows, err := d.reader.QueryContext(ctx,
		`SELECT `+emailImageColumns+` FROM email_images ORDER BY created_at DESC, id DESC`)
	if err != nil {
		return nil, fmt.Errorf("list email images: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var images []EmailImage
	for rows.Next() {
		img, err := scanEmailImage(rows)
		if err != nil {
			return nil, fmt.Errorf("scan email image: %w", err)
		}
		images = append(images, *img)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate email images: %w", err)
	}
	return images, nil
}

// GetEmailImage returns a library image by ID, or ErrNotFound.
func (d *DB) GetEmailImage(ctx context.Context, id int64) (*EmailImage, error) {
	row := d.reader.QueryRowContext(ctx,
		`SELECT `+emailImageColumns+` FROM email_images WHERE id = ?`, id)
	img, err := scanEmailImage(row)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get email image: %w", err)
	}
	return img, nil
}

// CreateEmailImage inserts a library image and sets img.ID and img.CreatedAt.
func (d *DB) CreateEmailImage(ctx context.Context, img *EmailImage) error {
	now := time.Now().UTC().Truncate(time.Second)
	res, err := d.writer.ExecContext(ctx, `
		INSERT INTO email_images (name, filename, content_type, size_bytes, width, height, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		img.Name, img.Filename, img.ContentType, img.SizeBytes, img.Width, img.Height, now.Format(tsLayout))
	if err != nil {
		return fmt.Errorf("create email image: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return fmt.Errorf("create email image id: %w", err)
	}
	img.ID = id
	img.CreatedAt = now
	return nil
}

// UpsertEmailImageByFilename inserts a library image or updates the metadata
// of the existing row with the same filename. Used by configuration import.
func (d *DB) UpsertEmailImageByFilename(ctx context.Context, img *EmailImage) error {
	createdAt := img.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	_, err := d.writer.ExecContext(ctx, `
		INSERT INTO email_images (name, filename, content_type, size_bytes, width, height, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(filename) DO UPDATE SET
			name         = excluded.name,
			content_type = excluded.content_type,
			size_bytes   = excluded.size_bytes,
			width        = excluded.width,
			height       = excluded.height`,
		img.Name, img.Filename, img.ContentType, img.SizeBytes, img.Width, img.Height,
		createdAt.UTC().Format(tsLayout))
	if err != nil {
		return fmt.Errorf("upsert email image: %w", err)
	}
	return nil
}

// DeleteEmailImage removes a library image row by ID, or returns ErrNotFound.
func (d *DB) DeleteEmailImage(ctx context.Context, id int64) error {
	res, err := d.writer.ExecContext(ctx, `DELETE FROM email_images WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete email image: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
