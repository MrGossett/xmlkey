package xmlkey

import (
	"crypto/rsa"
	"encoding/xml"
	"math/big"
)

// Parse will parse an XML-encoded RSA key into a *rsa.PrivateKey
func Parse(bs []byte) (*rsa.PrivateKey, error) {
	var key keyXML
	if err := xml.Unmarshal(bs, &key); err != nil {
		return nil, err
	}

	var retKey rsa.PrivateKey

	if key.HasPublicKey() {
		retKey.PublicKey = rsa.PublicKey{
			N: key.Modulus.BigInt(),
			E: key.Exponent.Integer(),
		}
	}
	if key.HasPrivateKey() {
		retKey.D = key.D.BigInt()
		retKey.Primes = []*big.Int{
			key.P.BigInt(),
			key.Q.BigInt(),
		}
		retKey.Precomputed = rsa.PrecomputedValues{
			Dp:        key.DP.BigInt(),
			Dq:        key.DQ.BigInt(),
			Qinv:      key.InverseQ.BigInt(),
			CRTValues: []rsa.CRTValue{},
		}
	}

	return &retKey, nil
}
