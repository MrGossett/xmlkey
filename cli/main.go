package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"io/ioutil"
	"log"
	"os"

	"github.com/MrGossett/xmlkey"
)

func main() {
	var in, out string
	flag.StringVar(&in, "in", "STDIN", "The file containing the XML key to parse")
	flag.StringVar(&out, "out", "STDOUT", "The file into which the PEM-encoded key should be written")
	flag.Parse()

	bs, err := ioutil.ReadAll(infile(in))
	if err != nil {
		log.Fatal(err)
	}

	key, err := xmlkey.Parse(bs)
	if err != nil {
		log.Fatal(err)
	}

	err = pem.Encode(outfile(out), &pem.Block{
		Bytes: x509.MarshalPKCS1PrivateKey(key),
		Type:  "RSA PRIVATE KEY",
	})
	if err != nil {
		log.Fatal(err)
	}
}

func outfile(path string) *os.File {
	if path == "STDOUT" {
		return os.Stdout
	}

	outFile, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}

	return outFile
}

func infile(path string) *os.File {
	if path == "STDIN" {
		return os.Stdin
	}

	inFile, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}

	return inFile
}
