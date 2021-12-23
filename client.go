package wkd

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/crypto/openpgp"
)

// Discover retrieves keys associated to an email address.
func Discover(addr string) ([]*openpgp.Entity, error) {
	local, domain, err := splitAddress(strings.ToLower(addr))
	if err != nil {
		return nil, err
	}
	urlEnd := "/hu/" + hashLocal(local) + "?l=" + url.QueryEscape(local)

	keys, err := getKeys("https://openpgpkey." + domain + Base + "/" + domain + urlEnd)
	if err == nil {
		return keys, nil
	}

	// The SRV reccord has being deprecated, kept here for backwards compatibility
	_, addrs, err := net.LookupSRV("openpgpkey", "tcp", domain)
	if dnsErr, ok := err.(*net.DNSError); ok {
		if dnsErr.IsTemporary {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	if len(addrs) > 0 {
		addr := addrs[0]
		if addr.Target == domain || strings.HasSuffix(addr.Target, "."+domain) {
			domain = fmt.Sprintf("%v:%v", addr.Target, addr.Port)
		}
	}

	return getKeys("https://" + domain + Base + urlEnd)
}

func getKeys(url string) ([]*openpgp.Entity, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return openpgp.ReadKeyRing(resp.Body)
}
