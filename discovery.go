package wks

import (
	"crypto/sha1"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/tv42/zbase32"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

func splitAddress(addr string) (local, domain string, err error) {
	parts := strings.Split(addr, "@")
	if len(parts) != 2 {
		return "", "", errors.New("wks: invalid email address")
	}
	return parts[0], parts[1], nil
}

// Discover retrieves keys associated to an email address.
func Discover(addr string) ([]*openpgp.Entity, error) {
	local, domain, err := splitAddress(strings.ToLower(addr))
	if err != nil {
		return nil, err
	}

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

	hashedLocal := sha1.Sum([]byte(local))
	url := "https://"+domain+"/.well-known/openpgpkey/hu/" + zbase32.EncodeToString(hashedLocal[:])
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	r := packet.NewReader(resp.Body)
	var entities []*openpgp.Entity
	for {
		e, err := openpgp.ReadEntity(r)
		if err == io.EOF {
			break
		} else if err != nil {
			return entities, err
		}

		entities = append(entities, e)
	}

	return entities, nil
}
