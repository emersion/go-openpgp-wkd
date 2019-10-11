package wkd

import (
	"os"
	"path/filepath"

	"golang.org/x/crypto/openpgp"
)

type Dir string

func (dir Dir) Init() error {
	if err := os.MkdirAll(string(dir), 0755); err != nil {
		return err
	}

	f, err := os.Create(filepath.Join(string(dir), "policy"))
	if err != nil {
		return err
	}
	defer f.Close()

	if err := writePolicy(f); err != nil {
		return err
	}
	return f.Close()
}

func (dir Dir) add(hash string, pubkey *openpgp.Entity) error {
	f, err := os.Create(filepath.Join(string(dir), "hu", hash))
	if err != nil {
		return err
	}
	defer f.Close()

	if err := pubkey.Serialize(f); err != nil {
		return err
	}

	return f.Close()
}

func (dir Dir) Add(pubkeys []*openpgp.Entity) error {
	if err := os.MkdirAll(filepath.Join(string(dir), "hu"), 0755); err != nil {
		return err
	}

	for _, e := range pubkeys {
		for _, ident := range e.Identities {
			addr := ident.UserId.Email
			hash, err := HashAddress(addr)
			if err != nil {
				return err
			}

			if err := dir.add(hash, e); err != nil {
				return err
			}
		}
	}

	return nil
}
