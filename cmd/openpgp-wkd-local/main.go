package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/emersion/go-openpgp-wkd"
	"golang.org/x/crypto/openpgp"
)

func main() {
	flag.Parse()

	switch flag.Arg(0) {
	case "add":
		keys, err := openpgp.ReadKeyRing(os.Stdin)
		if err != nil {
			log.Fatal(err)
		}

		dir := wkd.Dir(".")
		if err := dir.Init(); err != nil {
			log.Fatal(err)
		}

		if err := dir.Add(keys); err != nil {
			log.Fatal(err)
		}
	default:
		fmt.Fprintf(os.Stderr, "usage: openpgp-wkd-local add <key.pgp\n")
	}
}
