package wkd_test

import (
	"log"

	"github.com/emersion/go-openpgp-wkd"
)

func ExampleDiscover() {
	pubkeys, err := wkd.Discover("me@davlgd.fr")
	if err != nil {
		log.Fatal(err)
	}

	log.Println(pubkeys)
}
