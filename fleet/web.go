package fleet

import (
	"embed"
	"fmt"
	"io/fs"
	"net/http"
	"strings"
	"time"
)

//go:embed all:web
var webFS embed.FS

// registerWebUI attaches the embedded dashboard to the mux. Files live under
// fleet/web — the whole tree is baked into the binary via go:embed, so there
// is nothing to deploy alongside `xtop hub`.
//
// Routes:
//   /           → web/index.html
//   /static/*   → web/static/*   (css, js)
//   /favicon.ico → 404 (silences noisy browsers)
func (h *Hub) registerWebUI(mux *http.ServeMux) {
	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		// Falls through to the minimal landing stub if embed fails somehow
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(landingFallback))
		})
		return
	}

	// /static/* — revalidate every load so a hub upgrade instantly pushes
	// the new JS/CSS to connected browsers. http.FileServer sets an ETag
	// derived from the embed.FS file, so the 304-round-trip stays cheap.
	staticFS, err := fs.Sub(sub, "static")
	if err == nil {
		fileSrv := http.FileServer(http.FS(staticFS))
		mux.Handle("/static/", http.StripPrefix("/static/", revalidateAlways(fileSrv)))
	}

	// /favicon.ico — explicit 404 so browsers stop retrying.
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})

	// /  (and /index.html) → index.html. On every HTML load we set the
	// auth cookie so follow-up fetch() + EventSource calls from the
	// embedded dashboard pass the hub's token check without any JS
	// plumbing. The cookie is Strict-SameSite + HttpOnly; the hub token
	// is the trust anchor, so exposing it to the same origin the hub
	// already serves is no worse than the header path.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && r.URL.Path != "/index.html" {
			http.NotFound(w, r)
			return
		}
		data, err := fs.ReadFile(sub, "index.html")
		if err != nil {
			http.Error(w, "index missing", http.StatusInternalServerError)
			return
		}
		// Rewrite static asset URLs to include a build-version query
		// string so any upgrade of the hub auto-busts browser caches.
		// Pairs with Cache-Control:no-cache on /static/* — redundant on
		// its own but guarantees correctness even for clients with
		// broken revalidation.
		body := strings.ReplaceAll(string(data),
			`href="/static/style.css"`,
			`href="/static/style.css?v=`+buildStamp+`"`)
		body = strings.ReplaceAll(body,
			`src="/static/app.js"`,
			`src="/static/app.js?v=`+buildStamp+`"`)
		if h.cfg.AuthToken != "" {
			secure := r.TLS != nil
			http.SetCookie(w, &http.Cookie{
				Name:     webTokenCookie,
				Value:    h.cfg.AuthToken,
				Path:     "/",
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
				Secure:   secure,
				// No MaxAge → session cookie. Browsers re-ask the hub
				// for a fresh one on every new session.
			})
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(body))
	})
}

// buildStamp is a stable-per-binary token used to cache-bust /static URLs
// on HTML reload. Generated at process start so every running hub uses the
// same stamp; upgrading the hub produces a new stamp, forcing a fresh fetch.
var buildStamp = fmt.Sprintf("%d", time.Now().UnixNano())

// revalidateAlways sets the conservative "always ask the server" policy so
// redeploys never get stuck on a browser's stale copy of app.js/style.css.
// ETags still provide 304 short-circuits for unchanged files — near-zero
// cost per reload, maximum correctness.
func revalidateAlways(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache, must-revalidate")
		next.ServeHTTP(w, r)
	})
}

// landingFallback is the tiny page served when go:embed somehow fails. Should
// never be reached in normal builds — it's a safety net, not documentation.
const landingFallback = `<!DOCTYPE html>
<html><body style="font-family:sans-serif;padding:2em;background:#282a36;color:#f8f8f2">
<h1 style="color:#bd93f9">xtop hub</h1>
<p>Dashboard assets failed to load. The hub's JSON + SSE API is still running at:</p>
<ul>
  <li>GET /v1/hosts</li>
  <li>GET /v1/host/{hostname}</li>
  <li>GET /v1/incidents?hours=24</li>
  <li>GET /v1/stream</li>
  <li>GET /health</li>
</ul>
</body></html>`
