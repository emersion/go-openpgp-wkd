package wkd

import (
	"io"
	"net/http"
	"strings"

	"golang.org/x/crypto/openpgp"
)

// Handler is a HTTP WKD handler.
type Handler struct {
	// Discover retrieves keys for an address. If there's no key available for
	// this address, ErrNotFound should be returned.
	Discover func(hash string) ([]*openpgp.Entity, error)
}

func (h *Handler) servePolicy(w http.ResponseWriter, r *http.Request) {
	io.WriteString(w, "protocol-version: 6\n")
}

func (h *Handler) serveDiscovery(w http.ResponseWriter, r *http.Request, hash string) {
	pubkeys, err := h.Discover(hash)
	if err == ErrNotFound {
		http.NotFound(w, r)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/octet-string")
	for _, e := range pubkeys {
		e.Serialize(w)
	}
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

	if strings.HasPrefix(path, "/hu/") {
		hash := strings.TrimPrefix(path, "/hu/")
		h.serveDiscovery(w, r, hash)
		return
	}

	http.NotFound(w, r)
}
