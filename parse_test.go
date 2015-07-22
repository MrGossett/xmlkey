package xmlkey

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/xml"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	t.Parallel()

	expected := newKey(t)
	testKey := keyToKeyXML(expected)
	keyXML, err := xml.Marshal(testKey)
	require.NoError(t, err)

	actual, err := Parse(keyXML)

	assert.NoError(t, err)
	assert.Equal(t, expected.E, actual.E)
}

func TestParsePublic(t *testing.T) {
	t.Parallel()

	expected := &rsa.PrivateKey{PublicKey: newKey(t).PublicKey}
	testKey := keyToKeyXML(expected)
	keyXML, err := xml.Marshal(testKey)
	require.NoError(t, err)

	actual, err := Parse(keyXML)

	assert.NoError(t, err)
	assert.Equal(t, expected.E, actual.E)
}

func newKey(t *testing.T) *rsa.PrivateKey {
	testKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
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