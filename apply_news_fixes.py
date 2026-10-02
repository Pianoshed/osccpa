"""
Run from the project root (the folder with app.py and templates/):
    python apply_news_fixes.py

Fixes:
  1. 404 on /news/<id>/link-preview  -> adds the missing route to app.py
  2. 404 on /static/gallery/gal10.jpeg -> templates/news.html no longer points at the missing file
Backups are saved as app.py.bak and templates/news.html.bak. Safe to run twice.
"""
import sys, shutil

APP = "app.py"
NEWS = "templates/news.html"

ROUTE = '''
# ---------------------------------------------------------------------------
# NEWS: external link previews (title / description / image of the post's link)
# The /news page calls this once per post that has a link. The server fetches
# the page, reads its Open Graph tags and returns them as JSON. Results are
# cached in memory, and private/internal addresses are never fetched.
# ---------------------------------------------------------------------------
PREVIEW_TTL_OK = 6 * 3600
PREVIEW_TTL_FAIL = 30 * 60
PREVIEW_MAX_BYTES = 400_000
PREVIEW_TIMEOUT = 5
PREVIEW_MAX_REDIRECTS = 3
PREVIEW_HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; OCCPA-LinkPreview/1.0; +https://www.occpa.on.gov.ng)",
    "Accept": "text/html,application/xhtml+xml",
    "Accept-Language": "en",
}
_preview_cache = {}          # link -> (expires_at, data_or_None)
_preview_lock = threading.Lock()

def _is_public_host(host):
    try:
        infos = socket.getaddrinfo(host, None)
        return bool(infos) and all(ipaddress.ip_address(i[4][0]).is_global for i in infos)
    except (socket.gaierror, ValueError):
        return False

class _MetaParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.meta, self.title, self._in_title = {}, "", False
    def handle_starttag(self, tag, attrs):
        if tag == "meta":
            a = dict(attrs)
            key = (a.get("property") or a.get("name") or "").lower()
            val = a.get("content")
            if key and val and key not in self.meta:
                self.meta[key] = val.strip()
        elif tag == "title" and not self.title:
            self._in_title = True
    def handle_data(self, data):
        if self._in_title:
            self.title += data
    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False

def _fetch_preview(url):
    """Return {'title','description','image','url'} or None. Redirects are followed by hand
    so every hop is checked against the public-host rule."""
    current = url
    for _ in range(PREVIEW_MAX_REDIRECTS + 1):
        u = urlparse(current)
        if u.scheme not in ("http", "https") or not u.hostname or not _is_public_host(u.hostname):
            return None
        try:
            r = requests.get(current, headers=PREVIEW_HEADERS, timeout=PREVIEW_TIMEOUT,
                             stream=True, allow_redirects=False)
        except requests.RequestException:
            return None
        try:
            if r.status_code in (301, 302, 303, 307, 308):
                loc = r.headers.get("Location")
                if not loc:
                    return None
                current = urljoin(current, loc)
                continue
            ctype = r.headers.get("Content-Type", "").lower()
            if r.status_code != 200 or "html" not in ctype:
                return None
            raw = b""
            for chunk in r.iter_content(16384):
                raw += chunk
                if len(raw) >= PREVIEW_MAX_BYTES:
                    break
            enc = r.encoding if (r.encoding and "charset" in ctype) else "utf-8"
            text = raw.decode(enc, errors="replace")
        finally:
            r.close()

        p = _MetaParser()
        try:
            p.feed(text)
        except Exception:
            pass
        m = p.meta
        title = m.get("og:title") or m.get("twitter:title") or p.title.strip()
        desc = m.get("og:description") or m.get("twitter:description") or m.get("description") or ""
        img = m.get("og:image") or m.get("twitter:image") or ""
        if img:
            img = urljoin(current, img)
            if img.startswith("http://"):
                img = "https://" + img[7:]          # avoid mixed-content blocking
            if not img.startswith("https://"):
                img = ""
        if not title and not desc:
            return None
        return {"title": title[:200], "description": desc[:300], "image": img, "url": current}
    return None

@app.route("/news/<int:post_id>/link-preview")
def news_link_preview(post_id):
    post = NewsPost.query.filter_by(id=post_id, published=True).first_or_404()
    link = (post.link or "").strip()
    if not link:
        return jsonify(error="no link")
    if rate_limited("preview", 240, 60):
        return jsonify(error="rate limited"), 429

    now = time.time()
    with _preview_lock:
        hit = _preview_cache.get(link)
    if hit and hit[0] > now:
        data = hit[1]
    else:
        data = _fetch_preview(link)
        with _preview_lock:
            if len(_preview_cache) > 500:
                for k in [k for k, v in _preview_cache.items() if v[0] < now]:
                    _preview_cache.pop(k, None)
            _preview_cache[link] = (now + (PREVIEW_TTL_OK if data else PREVIEW_TTL_FAIL), data)

    # Always 200: when a site blocks previews the page just keeps its "Read full story" button
    # (the page script removes the card) and the browser console stays clean.
    resp = jsonify(data or {"error": "Preview unavailable"})
    resp.headers["Cache-Control"] = "public, max-age=3600"
    return resp
'''

def patch(path, edits):
    src = open(path, encoding="utf-8").read()
    out = src
    for old, new, label in edits:
        applied = (new in out) if new else (old not in out)
        if applied:
            print(f"  skip (already applied): {label}")
            continue
        if old not in out:
            sys.exit(f"  FAILED: could not find the text for: {label} in {path}")
        out = out.replace(old, new)
        print(f"  ok: {label}")
    if out != src:
        shutil.copy(path, path + ".bak")
        open(path, "w", encoding="utf-8").write(out)

print("Patching", APP)
patch(APP, [
    ("import threading\n", "import threading\nimport socket\nimport ipaddress\nfrom html.parser import HTMLParser\n", "imports"),
    ("from urllib.parse import quote, urlparse, parse_qs",
     "from urllib.parse import quote, urlparse, parse_qs, urljoin", "urljoin import"),
    ('    return render_template("news.html", news_posts=news_posts)\n',
     '    return render_template("news.html", news_posts=news_posts)\n' + ROUTE, "link-preview route"),
])

print("Patching", NEWS)
patch(NEWS, [
    ("poster=\"{{ url_for('static', filename='gallery/gal10.jpeg') }}\"",
     "poster=\"{{ url_for('static', filename='gallery/gal1.jpeg') }}\"", "video poster -> gal1.jpeg"),
    ("""          <img src="{{ url_for('static', filename='gallery/gal10.jpeg') }}" alt="Event 10" loading="lazy" decoding="async">\n""",
     "", "remove missing gal10 from gallery"),
    ('<img class="link-preview-image" alt="" loading="lazy" decoding="async">',
     '<img class="link-preview-image" alt="" loading="lazy" decoding="async" referrerpolicy="no-referrer">',
     "no-referrer on preview images"),
])
print("Done. Restart / redeploy the app.")
