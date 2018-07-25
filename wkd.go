// wkd implements OpenPGP Web Key Directory, defined in
// https://tools.ietf.org/html/draft-koch-openpgp-webkey-service-06
package wkd

import (
	"crypto/sha1"
	"errors"
	"strings"

	"github.com/tv42/zbase32"
)

const wellKnownBase = "/.well-known/openpgpkey"

// ErrNotFound is returned when the directory doesn't contain a public key for
// the provided address.
var ErrNotFound = errors.New("wkd: not found")

func splitAddress(addr string) (local, domain string, err error) {
	parts := strings.Split(addr, "@")
	if len(parts) != 2 {
		return "", "", errors.New("wkd: invalid email address")
	}
	return parts[0], parts[1], nil
}

func hashLocal(local string) string {
	local = strings.ToLower(local)
	hashedLocal := sha1.Sum([]byte(local))
	return zbase32.EncodeToString(hashedLocal[:])
}

// HashAddress returns the WKD hash for the local part of a given email address.
func HashAddress(addr string) (string, error) {
	local, _, err := splitAddress(addr)
	if err != nil {
		return "", err
	}
	return hashLocal(local), nil
}
