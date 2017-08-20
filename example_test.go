package wks_test

import (
	"log"

	"github.com/emersion/go-openpgp-wks"
)

func ExampleDiscover() {
	pubkeys, err := wks.Discover("me@davlgd.fr")
	if err != nil {
		log.Fatal(err)
	}

	log.Println(pubkeys)
}
