package xmlkey

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/xml"
	"math/big"
	"reflect"
	"testing"
)

func TestParse(t *testing.T) {
	t.Parallel()

	expected := newKey(t)
	testKey := keyToKeyXML(expected)

	keyXML, err := xml.Marshal(testKey)
	fatalIf(t, err)

	actual, err := Parse(keyXML)
	fatalIf(t, err)

	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("Keys are not equal.\n\tExpected: %v\n\tActual: %v", expected, actual)
	}
}

func TestParsePublic(t *testing.T) {
	t.Parallel()

	expected := &rsa.PrivateKey{PublicKey: newKey(t).PublicKey}
	testKey := keyToKeyXML(expected)

	keyXML, err := xml.Marshal(testKey)
	fatalIf(t, err)

	actual, err := Parse(keyXML)
	fatalIf(t, err)

	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("Keys are not equal.\n\tExpected: %v\n\tActual: %v", expected, actual)
	}
}

func TestParseBase64(t *testing.T) {
	t.Parallel()

	expected := newKey(t)
	testKey := keyToKeyXML(expected)

	keyXML, err := xml.Marshal(testKey)
	fatalIf(t, err)

	b64 := make([]byte, base64.StdEncoding.EncodedLen(len(keyXML)))
	base64.StdEncoding.Encode(b64, keyXML)

	actual, err := Parse(b64)
	fatalIf(t, err)

	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("Keys are not equal.\n\tExpected: %v\n\tActual: %v", expected, actual)
	}
}

func TestParsePublicBase64(t *testing.T) {
	t.Parallel()

	expected := &rsa.PrivateKey{PublicKey: newKey(t).PublicKey}
	testKey := keyToKeyXML(expected)

	keyXML, err := xml.Marshal(testKey)
	fatalIf(t, err)

	b64 := make([]byte, base64.StdEncoding.EncodedLen(len(keyXML)))
	base64.StdEncoding.Encode(b64, keyXML)

	actual, err := Parse(b64)
	fatalIf(t, err)

	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("Keys are not equal.\n\tExpected: %v\n\tActual: %v", expected, actual)
	}
}

func newKey(t *testing.T) *rsa.PrivateKey {
	testKey, err := rsa.GenerateKey(rand.Reader, 2048)
	fatalIf(t, err)

	return testKey
}

func keyToKeyXML(key *rsa.PrivateKey) keyXML {
	var retKey keyXML
	if key.N != nil && key.E != 0 {
		retKey.publicKeyXML = publicKeyXML{
			Modulus:  &bigInt{key.N},
			Exponent: &bigInt{new(big.Int).SetInt64(int64(key.E))},
		}
	}

	if key.D != nil {
		retKey.privateKeyXML = privateKeyXML{
			D:        &bigInt{key.D},
			P:        &bigInt{key.Primes[0]},
			Q:        &bigInt{key.Primes[1]},
			DP:       &bigInt{key.Precomputed.Dp},
			DQ:       &bigInt{key.Precomputed.Dq},
			InverseQ: &bigInt{key.Precomputed.Qinv},
		}
	}
	return retKey
}

func fatalIf(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}
