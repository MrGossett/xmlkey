package main

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"log"
	"os"

	"github.com/MrGossett/xmlkey"
)

func main() {
	bs, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		log.Fatal(err)
	}

	key, err := xmlkey.Parse(bs)
	if err != nil {
		log.Fatal(err)
	}

	err = pem.Encode(os.Stdout, &pem.Block{
		Bytes: x509.MarshalPKCS1PrivateKey(key),
		Type:  "RSA PRIVATE KEY",
	})
	if err != nil {
		log.Fatal(err)
	}
}
