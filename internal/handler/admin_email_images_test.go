package handler

import (
	"bytes"
	"context"
	"errors"
	"image"
	"image/color"
	"image/png"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/hanej/passport/internal/db"
)

func newEmailImagesHandler(t *testing.T, env *emailTemplatesTestEnv) (*AdminEmailImagesHandler, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "email-images")
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	return NewAdminEmailImagesHandler(env.db, stubEmailTemplatesRenderer(t), env.sm, env.audit, logger, dir), dir
}

func testPNG(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	img.Set(0, 0, color.RGBA{R: 255, A: 255})
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func uploadEmailImage(t *testing.T, env *emailTemplatesTestEnv, h *AdminEmailImagesHandler, cookies []*http.Cookie, filename, name string, data []byte) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, err := mw.CreateFormFile("image_file", filename)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fw.Write(data)
	_ = mw.WriteField("name", name)
	_ = mw.Close()

	req := httptest.NewRequest(http.MethodPost, "/admin/email-templates/images", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	env.sm.Middleware(http.HandlerFunc(h.Upload)).ServeHTTP(rec, req)
	return rec
}

func deleteEmailImage(env *emailTemplatesTestEnv, h *AdminEmailImagesHandler, cookies []*http.Cookie, id string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/admin/email-templates/images/"+id+"/delete", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	env.sm.Middleware(http.HandlerFunc(h.Delete)).ServeHTTP(rec, req)
	return rec
}

func TestAdminEmailImages_UploadValidPNG(t *testing.T) {
	env := setupEmailTemplatesTest(t)
	h, dir := newEmailImagesHandler(t, env)
	cookies := env.createAdminSession(t)

	rec := uploadEmailImage(t, env, h, cookies, "Company Logo.png", "", testPNG(t, 12, 7))
	if rec.Code != http.StatusFound {
		t.Fatalf("expected redirect, got %d", rec.Code)
	}

	images, err := env.db.ListEmailImages(context.Background())
	if err != nil || len(images) != 1 {
		t.Fatalf("expected one image, got %d (%v)", len(images), err)
	}
	img := images[0]
	if img.Name != "Company Logo" || img.ContentType != "image/png" || img.Width != 12 || img.Height != 7 {
		t.Errorf("unexpected image metadata: %+v", img)
	}
	if !strings.HasSuffix(img.Filename, ".png") || strings.Contains(img.Filename, "Logo") {
		t.Errorf("expected a server-generated .png filename, got %q", img.Filename)
	}
	if _, err := os.Stat(filepath.Join(dir, img.Filename)); err != nil {
		t.Errorf("expected file on disk: %v", err)
	}
}

func TestAdminEmailImages_UploadRejectsInvalidFiles(t *testing.T) {
	env := setupEmailTemplatesTest(t)
	h, _ := newEmailImagesHandler(t, env)
	cookies := env.createAdminSession(t)

	cases := map[string][]byte{
		"fake.png": []byte("<html>not an image</html>"),
		"logo.svg": []byte(`<svg xmlns="http://www.w3.org/2000/svg"></svg>`),
		"pic.webp": testPNG(t, 2, 2),
	}
	for name, data := range cases {
		if rec := uploadEmailImage(t, env, h, cookies, name, "", data); rec.Code != http.StatusFound {
			t.Errorf("%s: expected redirect, got %d", name, rec.Code)
		}
	}

	images, _ := env.db.ListEmailImages(context.Background())
	if len(images) != 0 {
		t.Errorf("expected all uploads rejected, got %d images", len(images))
	}
}

func TestAdminEmailImages_UploadRejectsOversize(t *testing.T) {
	env := setupEmailTemplatesTest(t)
	h, _ := newEmailImagesHandler(t, env)
	cookies := env.createAdminSession(t)

	big := append(testPNG(t, 2, 2), make([]byte, maxEmailImageBytes)...)
	uploadEmailImage(t, env, h, cookies, "big.png", "", big)

	images, _ := env.db.ListEmailImages(context.Background())
	if len(images) != 0 {
		t.Errorf("expected oversize upload rejected, got %d images", len(images))
	}
}

func TestAdminEmailImages_DeleteBlockedWhileInUse(t *testing.T) {
	env := setupEmailTemplatesTest(t)
	h, dir := newEmailImagesHandler(t, env)
	cookies := env.createAdminSession(t)
	ctx := context.Background()

	uploadEmailImage(t, env, h, cookies, "logo.png", "Logo", testPNG(t, 4, 4))
	images, _ := env.db.ListEmailImages(ctx)
	img := images[0]
	id := strconv.FormatInt(img.ID, 10)

	if err := env.db.SaveEmailTemplate(ctx, &db.EmailTemplate{
		TemplateType: "password_expiration:corp-ad",
		Subject:      "s",
		BodyHTML:     `<img src="/uploads/email-images/` + img.Filename + `">`,
	}); err != nil {
		t.Fatal(err)
	}

	// The list page reports which templates use the image.
	listReq := httptest.NewRequest(http.MethodGet, "/admin/email-templates/images", nil)
	for _, c := range cookies {
		listReq.AddCookie(c)
	}
	listRec := httptest.NewRecorder()
	env.sm.Middleware(http.HandlerFunc(h.List)).ServeHTTP(listRec, listReq)
	if !strings.Contains(listRec.Body.String(), "[Password Expiration Warning — corp-ad]") {
		t.Errorf("expected usage in list output, got %q", listRec.Body.String())
	}

	deleteEmailImage(env, h, cookies, id)
	if _, err := env.db.GetEmailImage(ctx, img.ID); err != nil {
		t.Fatalf("image should not be deleted while in use: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, img.Filename)); err != nil {
		t.Errorf("file should remain while in use: %v", err)
	}

	if err := env.db.DeleteEmailTemplate(ctx, "password_expiration:corp-ad"); err != nil {
		t.Fatal(err)
	}
	if rec := deleteEmailImage(env, h, cookies, id); rec.Code != http.StatusFound {
		t.Fatalf("expected redirect, got %d", rec.Code)
	}
	if _, err := env.db.GetEmailImage(ctx, img.ID); err == nil {
		t.Error("expected image row to be deleted")
	}
	if _, err := os.Stat(filepath.Join(dir, img.Filename)); !os.IsNotExist(err) {
		t.Errorf("expected file to be removed, stat err=%v", err)
	}
}

type emailImagesErrStore struct {
	*db.DB
	listImagesErr    error
	getImageErr      error
	createImageErr   error
	deleteImageErr   error
	listTemplatesErr error
}

func (s *emailImagesErrStore) ListEmailImages(ctx context.Context) ([]db.EmailImage, error) {
	if s.listImagesErr != nil {
		return nil, s.listImagesErr
	}
	return s.DB.ListEmailImages(ctx)
}

func (s *emailImagesErrStore) GetEmailImage(ctx context.Context, id int64) (*db.EmailImage, error) {
	if s.getImageErr != nil {
		return nil, s.getImageErr
	}
	return s.DB.GetEmailImage(ctx, id)
}

func (s *emailImagesErrStore) CreateEmailImage(ctx context.Context, img *db.EmailImage) error {
	if s.createImageErr != nil {
		return s.createImageErr
	}
	return s.DB.CreateEmailImage(ctx, img)
}

func (s *emailImagesErrStore) DeleteEmailImage(ctx context.Context, id int64) error {
	if s.deleteImageErr != nil {
		return s.deleteImageErr
	}
	return s.DB.DeleteEmailImage(ctx, id)
}

func (s *emailImagesErrStore) ListEmailTemplates(ctx context.Context) ([]db.EmailTemplate, error) {
	if s.listTemplatesErr != nil {
		return nil, s.listTemplatesErr
	}
	return s.DB.ListEmailTemplates(ctx)
}

func TestAdminEmailImages_ErrorPaths(t *testing.T) {
	env := setupEmailTemplatesTest(t)
	h, dir := newEmailImagesHandler(t, env)
	cookies := env.createAdminSession(t)
	ctx := context.Background()
	errBoom := errors.New("boom")

	uploadEmailImage(t, env, h, cookies, "logo.png", "Logo", testPNG(t, 2, 2))
	images, _ := env.db.ListEmailImages(ctx)
	id := strconv.FormatInt(images[0].ID, 10)

	serveList := func(h *AdminEmailImagesHandler) int {
		req := httptest.NewRequest(http.MethodGet, "/admin/email-templates/images", nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		env.sm.Middleware(http.HandlerFunc(h.List)).ServeHTTP(rec, req)
		return rec.Code
	}

	with := func(store *emailImagesErrStore) *AdminEmailImagesHandler {
		clone := *h
		store.DB = env.db
		clone.store = store
		return &clone
	}

	if code := serveList(with(&emailImagesErrStore{listImagesErr: errBoom})); code != http.StatusInternalServerError {
		t.Errorf("list with store error: expected 500, got %d", code)
	}
	if code := serveList(with(&emailImagesErrStore{listTemplatesErr: errBoom})); code != http.StatusOK {
		t.Errorf("list should still render when template usage can't be loaded, got %d", code)
	}

	// A failed DB insert must not leave an orphaned file behind.
	before, _ := os.ReadDir(dir)
	uploadEmailImage(t, env, with(&emailImagesErrStore{createImageErr: errBoom}), cookies, "x.png", "", testPNG(t, 2, 2))
	after, _ := os.ReadDir(dir)
	if len(after) != len(before) {
		t.Errorf("expected no new file after failed insert, had %d now %d", len(before), len(after))
	}

	// Upload with no file.
	req := httptest.NewRequest(http.MethodPost, "/admin/email-templates/images", strings.NewReader("name=x"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	env.sm.Middleware(http.HandlerFunc(h.Upload)).ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Errorf("upload without multipart: expected redirect, got %d", rec.Code)
	}

	// Unwritable directory.
	badDir := *h
	badDir.dir = filepath.Join(t.TempDir(), "missing", "dir")
	uploadEmailImage(t, env, &badDir, cookies, "y.png", "", testPNG(t, 2, 2))

	for _, tc := range []struct {
		name string
		h    *AdminEmailImagesHandler
		id   string
		gone bool
	}{
		{"bad id", h, "abc", false},
		{"not found", h, "99999", false},
		{"get error", with(&emailImagesErrStore{getImageErr: errBoom}), id, false},
		{"usage error", with(&emailImagesErrStore{listTemplatesErr: errBoom}), id, false},
		{"delete error", with(&emailImagesErrStore{deleteImageErr: errBoom}), id, false},
	} {
		if rec := deleteEmailImage(env, tc.h, cookies, tc.id); rec.Code != http.StatusFound {
			t.Errorf("%s: expected redirect, got %d", tc.name, rec.Code)
		}
		if _, err := env.db.GetEmailImage(ctx, images[0].ID); err != nil {
			t.Errorf("%s: image should not be deleted: %v", tc.name, err)
		}
	}
}

func TestFormatImageSize(t *testing.T) {
	for n, want := range map[int64]string{512: "512 B", 2048: "2 KB", 3 << 20: "3.0 MB"} {
		if got := formatImageSize(n); got != want {
			t.Errorf("formatImageSize(%d) = %q, want %q", n, got, want)
		}
	}
}
