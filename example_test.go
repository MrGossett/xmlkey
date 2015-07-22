package xmlkey_test

import (
	"encoding/base64"
	"fmt"
	"log"

	"github.com/MrGossett/xmlkey"
)

var keyXML = []byte(`
<RSAKeyValue>
	<Modulus>onEA/quULN8dZFtzls2EFHkunvUJonwy5A42RHcQmPjKWmp8YC/3vW9eWAOyk+8Fz8v/48L3Zm7u6iE0XS71WHyBG0CuwWz0DC1N+MyrhxaAb7finFKGR0CpvnX2OLDYWGxkmfwgtxSs2kWnmw1WuDR5MPlhyOYpF4vkzbMrG0UNhfm4cB7X4lpRsAqYBP8OfayeM7HMgQGP+a2YDsjwxtZGztP5Zze+Ymni8HbvDyZQdtmmHbaVgoIbfu9nUeZSX2+7Ge0uu47wT3eFMF/C1+X9wflFX4IXengkOIQ9kcWMNIUvHLlw1JRkeDWUo5dtQAtKtpYpoBYSlFD4SetocQ==</Modulus>
	<Exponent>AQAB</Exponent>
	<P>xnHGLoLaUlPnewlfjxBQFLh/V9tuYN0rDX7HbqRDBmxO8hS6WIBE5kdjSLxqcPIYpjZ6IqGScJJTcoQ3Ld1w8g2G+YoW27vS8srhSKH/QmfGriXetAItdseq8Q0ULccX2QPex18AwsIaV1OYFE6oEcNYmeUs/ZsJR3cYerQlOjU=</P>
	<Q>0Y4OThuq1dtC/9/suH6xkZyzj7bdamjfRNRW+rcW8kMk01bATH0yBUKVRmTiIzlarLpp7CuOmdN50167hlrfdNZJa53gqcb8iwlVRqHvaaLhH4msPxsGZKt6nV0zCvY0PSgh4EGtnYAB52qhmZByM5UqivMWecXvNTjWj0aGHM0=</Q>
	<DP>o+57FBMevaH4eKhem3WTYfqjn/VycmxiU2ym3VyuzdCNSugapF+aC01v1DdqCtHD0RLxxEgLDBmk+9YDK01iL2NDXENZ7L11XwKAJptEnhvSgixgk/20hwocybLPN53fsnPDBpoRq9HjJr60xBnSN5JTUBaFGx+HA9V7kGne0v0=</DP>
	<DQ>sV5qz0PtyktnH0q6g8KAq74V4eum531SlWChKl60JmQclGEWLOe+4eLklIupOKVAEXlLVGHdtmff8r95PBRIlQ0XYeZklW9erJQ+wKUqDqCVqesOhu9p7uWRyAZtwLZ5qtYALl+JAwmpEuYXV/KCJxT3yFpOyM13VfYA7Y6Ez3U=</DQ>
	<D>OQ4uBkVnvzcC0NwaRm6bJMHHsUdqAetTyKyBPR0A9Gn2UTmzw+k1QBFc9tcdoz5CMVF66JnzYcQ3IH9XMB+tR0473sGiYAgP1DMZfvkMil9J73OMIdIOnfpFZMN0H0dmRfCUiU14hDW73NK4YwqVWg/8PUpqoTDOYBnf3KxAyMux/NMZJq6veuWjr5zrD/ZY3laZ4ii85+QtgFIsWhPxCe2seqPGtXpn1GRBxrMex3l3+NRhOIm+GfAeUzK4CZWR55L4kgryTB9aa5ZOiqTSGHbuVZrwQ5/ND9lfCth92M9suOMr31LXmEqhHakvzfYTzQwSGPu85dRTcKtBFA7x0Q==</D>
	<InverseQ>SgDF7RYgbTfq/N41oHXR+2/aHqxoficCvbn8WV2MyiIhHMIPWVigRwBzPXyY/kUIcKTUhR9zaZPEAJ2OBZDQ4NI+hizi29bTT6JwxEHk6p0j5ZQDsy0M0dQWrDlEXEXid8q8+vIEutr97CYET97NQp8tp9xS9xIkPPjPqMufLA0=</InverseQ>
</RSAKeyValue>`)

func ExampleParse() {
	key, err := xmlkey.Parse(keyXML)
	if err != nil {
		log.Fatal(err)
	}

	if err := key.Validate(); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Exponent: %d", key.PublicKey.E)

	// Output: Exponent: 65537
}

func ExampleParse_base64() {
	b64 := make([]byte, base64.StdEncoding.EncodedLen(len(keyXML)))
	base64.StdEncoding.Encode(b64, keyXML)
	key, err := xmlkey.Parse(b64)
	if err != nil {
		log.Fatal(err)
	}

	if err := key.Validate(); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Exponent: %d", key.PublicKey.E)

	// Output: Exponent: 65537
}
