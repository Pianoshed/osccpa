# News Update feature — setup notes

## 1. Install Pillow
Used to compress/re-encode every uploaded news photo.
```
pip install Pillow
```
(Add `Pillow` to your `requirements.txt`.)

## 2. Add the two new database tables
The app uses Flask-Migrate and does **not** call `db.create_all()`, so run a migration:
```
flask db migrate -m "add news_posts and news_images tables"
flask db upgrade
```
This adds `news_posts` (the update itself) and `news_images` (its photos, one row each).

## 3. Make sure `static/news/` exists and is writable
The app creates it automatically on startup (`os.makedirs(..., exist_ok=True)`), but
double-check it's inside your deployed app's persistent storage, not an ephemeral path.

## What changed
- **`app.py`**
  - New models: `NewsPost` (title, tag, summary, body, external link, flash/published flags)
    and `NewsImage` (one row per photo, so a post can carry several).
  - `save_news_image()` — validates each upload, then fully re-encodes it with Pillow:
    resizes to a 1600px max side, strips EXIF/GPS metadata, and saves as a fresh JPEG
    (quality 78). Re-encoding also neutralises "polyglot" files (an image crafted to smuggle
    an HTML/script payload past a magic-byte check) since only pixel data is ever read back.
  - `save_news_images()` — same, for a batch, enforcing `NEWS_MAX_IMAGES` (8) per post.
  - Per-file size cap (`NEWS_MAX_UPLOAD_MB` = 10 MB) enforced independently of the shared
    request-body limit, so raising that shared limit for multi-photo uploads didn't loosen
    the original single-file evidence-upload cap.
  - New admin routes: `POST /admin/news/create`, `/admin/news/update/<id>`,
    `/admin/news/delete/<id>` — all CSRF-protected and login-gated, matching the existing
    complaints/contacts routes.
  - `/`, `/news`, `/admin/dashboard` now pass real DB data instead of static content.
- **`templates/news.html`** — dynamic posts render at the top of the activities grid
  (newest first), reusing the existing card styles, read-more toggle, and pagination JS
  unchanged. Multi-photo posts show a photo-count badge and a small "more photos" gallery.
- **`templates/index.html`** — the homepage teaser card now pulls the latest published post,
  and a new "Flash" ticker strip shows up to 5 posts flagged as flash updates.
- **`templates/admin_dashboard.html`** — new "News" tab: a searchable table of all posts plus
  an add/edit modal (title, tag, summary, full story, up to 8 photos, external link,
  flash/published toggles). Editing shows existing photos as removable thumbnails.

## Notes / limits
- Up to **8 photos** per news update (comfortably above the "at least 5" requirement).
- Each photo: PNG/JPG/WEBP, under 10 MB raw, auto-compressed to a ~1 MB JPEG.
- Deleting a post or removing a photo deletes its file(s) from disk too — no orphaned files.
- Draft posts (`is_published` off) never appear on `/news` or the homepage, only in the
  admin dashboard, so you can prep a story before it goes live.
