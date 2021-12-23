package wkd

import (
	"context"
	"io"
	"net/http"
	"strings"
)

// Handler is a HTTP WKD handler.
type Handler struct {
	// Discover retrieves keys for an address. If there's no key available for
	// this address, ErrNotFound should be returned.
	// The returned io.Reader should read the binary representation of an OpenPGP key
	Discover func(ctx context.Context, hash, domain, local string) (io.Reader, error)
}

func (h *Handler) servePolicy(w http.ResponseWriter, r *http.Request) {
	writePolicy(w)
}

func (h *Handler) serveDiscovery(w http.ResponseWriter, r *http.Request, hash, domain, local string) {
	ctx := r.Context()
	pubkeys, err := h.Discover(ctx, hash, domain, local)
	if err == ErrNotFound {
		http.NotFound(w, r)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/octet-string")
	io.Copy(w, pubkeys)
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.URL.Path, Base) {
		http.NotFound(w, r)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, Base)

	if path == "/policy" {
		h.servePolicy(w, r)
		return
	}

	query := r.URL.Query()
	localPart := query.Get("l")

	if strings.HasPrefix(path, "/hu/") {
		hash := strings.TrimPrefix(path, "/hu/")
		h.serveDiscovery(w, r, hash, r.Host, localPart)
		return
	}

	pathParts := strings.Split(path, "/")
	if len(pathParts) == 4 && pathParts[2] == "hu" {
		hash := pathParts[3]
		domain := pathParts[1]
		h.serveDiscovery(w, r, hash, domain, localPart)
		return
	}

	http.NotFound(w, r)
}
