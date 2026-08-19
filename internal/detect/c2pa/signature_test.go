package c2pa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// TestTheSignerIsReadOutOfTheCertificate: what a credential says about who signed
// it comes from the certificate it ships, and augur prints that and nothing more.
// This checks the reading; it is deliberately not a check that the signature is
// valid, because augur does not make that claim — see
// docs/decisions/provenance-is-read-not-trusted.md.
func TestTheSignerIsReadOutOfTheCertificate(t *testing.T) {
	der := selfSignedCertificate(t, "Some Signer", "Some Organisation")

	// A COSE_Sign1: protected header, unprotected header, detached payload,
	// signature. The certificate chain rides in protected header 33.
	cose := []byte{0x84} // array of four
	cose = append(cose, cborEncode(coseProtected(-7, der))...)
	cose = append(cose, cborEncode(map[string]any{})...)
	cose = append(cose, 0xf6) // detached payload
	cose = append(cose, cborEncode([]byte{0x01, 0x02})...)

	store := buildStore(t, manifestOptions{
		claim:     map[string]any{"claim_generator": "tool 1.0"},
		signature: cose,
	})

	s, err := Parse(store)
	if err != nil {
		t.Fatal(err)
	}
	signer, ok := s.Active().Signer()
	if !ok {
		t.Fatal("the signature box was not read")
	}
	if signer.CommonName != "Some Signer" || signer.Organisation != "Some Organisation" {
		t.Errorf("signer = %+v", signer)
	}
	if signer.Algorithm != "ES256" {
		t.Errorf("algorithm = %q", signer.Algorithm)
	}
	if got := signer.Description(); got != "Some Signer (Some Organisation), certificate issued by Some Signer" {
		t.Errorf("description = %q", got)
	}
}

func TestAnUnreadableSignatureIsNotReportedAsSigned(t *testing.T) {
	store := buildStore(t, manifestOptions{
		claim:     map[string]any{"claim_generator": "tool 1.0"},
		signature: []byte{0x01, 0x02, 0x03},
	})
	s, err := Parse(store)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Active().Signer(); ok {
		t.Fatal("three arbitrary bytes were read as a signature")
	}
	var said bool
	for _, row := range Read(store, nil).Rows() {
		if row.Key == "signature" && row.Value == "present, but augur could not read it" {
			said = true
		}
	}
	if !said {
		t.Error("the report should say the signature would not parse rather than omitting it")
	}
}

// coseProtected builds the protected header as the bstr-wrapped map COSE requires:
// algorithm at label 1, certificate chain at label 33.
func coseProtected(alg int64, der []byte) []byte {
	header := []byte{0xa2} // map of two
	header = append(header, 0x01)
	header = append(header, cborNegative(alg)...)
	header = append(header, 0x18, 33) // key 33
	header = append(header, cborEncode(der)...)
	return header
}

func cborNegative(n int64) []byte {
	return cborHead(1, uint64(-1-n))
}

func selfSignedCertificate(t *testing.T, commonName, organisation string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: commonName,
			// nolint:misspell // crypto/x509 spells the X.509 field this way.
			Organization: []string{organisation},
		},
		NotBefore: time.Unix(1700000000, 0),
		NotAfter:  time.Unix(1900000000, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
