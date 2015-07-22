package xmlkey

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"math/big"
)

type (
	keyXML struct {
		XMLName xml.Name `xml:"RSAKeyValue"`
		publicKeyXML
		privateKeyXML
	}

	publicKeyXML struct {
		Modulus, Exponent *bigInt
	}
	privateKeyXML struct {
		P, Q, DP, DQ, D, InverseQ *bigInt
	}

	bigInt struct{ *big.Int }
)

func (k keyXML) HasPublicKey() bool {
	return allNotEmpty(k.Exponent, k.Modulus)
}

func (k keyXML) HasPrivateKey() bool {
	return allNotEmpty(k.D, k.DP, k.DQ, k.InverseQ, k.P, k.Q)
}

func allNotEmpty(bis ...*bigInt) bool {
	for _, bi := range bis {
		if bi == nil || bi.IsEmpty() {
			return false
		}
	}
	return true
}

func (bi *bigInt) UnmarshalText(text []byte) error {
	bs := make([]byte, base64.StdEncoding.DecodedLen(len(text)))
	if _, err := base64.StdEncoding.Decode(bs, text); err != nil {
		return err
	}
	if bi.Int == nil {
		bi.Int = new(big.Int)
	}
	bi.Int.SetBytes(bytes.TrimRight(bs, "\x00"))
	return nil
}

func (bi *bigInt) MarshalText() ([]byte, error) {
	text := make([]byte, base64.StdEncoding.EncodedLen(len(bi.Bytes())))
	base64.StdEncoding.Encode(text, bi.Bytes())
	return text, nil
}

func (bi bigInt) BigInt() *big.Int {
	return bi.Int
}

func (bi bigInt) Integer() int {
	return int(bi.Int64())
}

func (bi bigInt) IsEmpty() bool {
	return bi.Int == nil
}
