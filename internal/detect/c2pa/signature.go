package c2pa

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// The claim is signed as a COSE_Sign1 structure: a protected header, an
// unprotected header, a detached payload, and the signature. augur reads two
// things out of it — who the certificate says signed, and when a timestamp
// authority says it happened.
//
// It does NOT verify the signature or the certificate chain, and does not imply
// that it has. Verifying a chain means having a trust list to verify it against;
// a check that stops at "the certificate parsed" and gets reported as "signed by
// Acme" is exactly the kind of half-answer that makes a provenance tool worse
// than none. What is printed here is what the file claims about itself.

// Signer is the identity a manifest's certificate asserts.
type Signer struct {
	// CommonName and Organisation come from the end-entity certificate's subject.
	CommonName   string
	Organisation string
	// Issuer names the certificate authority that signed it.
	Issuer string
	// NotBefore and NotAfter bound the certificate's validity. They are not the
	// signing time — a certificate is valid for years — but they are what is
	// available when there is no timestamp.
	NotBefore, NotAfter time.Time
	// Algorithm is the COSE signature algorithm, named.
	Algorithm string
	// TimeStamp is when an RFC 3161 authority countersigned the claim, when the
	// manifest carries such a token. This is the closest thing to "when was this
	// file signed" that a file can carry.
	TimeStamp time.Time
	// ChainLength is how many certificates the manifest shipped.
	ChainLength int
}

// Signer reads the COSE structure. It returns false when there is nothing
// readable there, which is itself worth reporting: a manifest whose signature box
// will not parse is not a manifest anyone should be reassured by.
func (m *Manifest) Signer() (Signer, bool) {
	if len(m.Signature) == 0 {
		return Signer{}, false
	}
	cose, err := cborDecode(m.Signature)
	if err != nil {
		return Signer{}, false
	}
	parts := cborArray(cose)
	if len(parts) != 4 {
		return Signer{}, false
	}

	var out Signer
	protected := map[any]any{}
	if raw := cborBytes(parts[0]); len(raw) > 0 {
		if v, err := cborDecode(raw); err == nil {
			protected = cborMap(v)
		}
	}
	unprotected := cborMap(parts[1])

	if alg, ok := cborInt(protected[int64(1)]); ok {
		out.Algorithm = coseAlgorithm(alg)
	}

	chain := certificateChain(protected, unprotected)
	out.ChainLength = len(chain)
	if len(chain) > 0 {
		if cert, err := x509.ParseCertificate(chain[0]); err == nil {
			out.CommonName = cert.Subject.CommonName
			// nolint:misspell // "Organization" is how crypto/x509 spells the
			// X.509 field; the prose in this repo is British.
			if len(cert.Subject.Organization) > 0 {
				out.Organisation = cert.Subject.Organization[0]
			}
			out.Issuer = cert.Issuer.CommonName
			// nolint:misspell // as above: crypto/x509's own field name.
			if out.Issuer == "" && len(cert.Issuer.Organization) > 0 {
				out.Issuer = cert.Issuer.Organization[0] // nolint:misspell
			}
			out.NotBefore, out.NotAfter = cert.NotBefore, cert.NotAfter
		}
	}
	out.TimeStamp = timeStamp(unprotected)
	return out, out.CommonName != "" || out.Organisation != "" || out.Algorithm != ""
}

// certificateChain finds the x5chain header (COSE label 33), which producers put
// in either header, and which holds one certificate or an array of them.
func certificateChain(protected, unprotected map[any]any) [][]byte {
	for _, headers := range []map[any]any{protected, unprotected} {
		for _, key := range []any{int64(33), "x5chain"} {
			v, ok := headers[key]
			if !ok {
				continue
			}
			if der := cborBytes(v); len(der) > 0 {
				return [][]byte{der}
			}
			var chain [][]byte
			for _, item := range cborArray(v) {
				if der := cborBytes(item); len(der) > 0 {
					chain = append(chain, der)
				}
			}
			if len(chain) > 0 {
				return chain
			}
		}
	}
	return nil
}

// coseAlgorithm names the signature algorithm from its COSE identifier.
func coseAlgorithm(id int64) string {
	switch id {
	case -7:
		return "ES256"
	case -35:
		return "ES384"
	case -36:
		return "ES512"
	case -37:
		return "PS256"
	case -38:
		return "PS384"
	case -39:
		return "PS512"
	case -8:
		return "EdDSA"
	}
	return fmt.Sprintf("COSE algorithm %d", id)
}

// timeStamp digs the signing time out of an RFC 3161 token, which C2PA carries in
// the unprotected header under sigTst (v1) or sigTst2 (v2).
//
// The time inside is the one fact in a manifest that no producer can backdate on
// its own — a timestamp authority countersigned it — so it is worth the ASN.1 walk
// to get at.
func timeStamp(unprotected map[any]any) time.Time {
	for _, key := range []any{"sigTst", "sigTst2"} {
		v, ok := unprotected[key]
		if !ok {
			continue
		}
		for _, token := range cborArray(cborGet(v, "tstTokens")) {
			der := cborBytes(cborGet(token, "val"))
			if len(der) == 0 {
				continue
			}
			if t, err := timeFromToken(der); err == nil {
				return t
			}
		}
	}
	return time.Time{}
}

// timeFromToken unwraps a TimeStampToken far enough to read its genTime: a CMS
// ContentInfo wrapping SignedData, whose encapsulated content is the TSTInfo.
func timeFromToken(der []byte) (time.Time, error) {
	var ci struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
	}
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		return time.Time{}, err
	}

	var sd struct {
		Version          int
		DigestAlgorithms asn1.RawValue
		EncapContentInfo struct {
			EContentType asn1.ObjectIdentifier
			EContent     []byte `asn1:"tag:0,explicit,optional"`
		}
	}
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return time.Time{}, err
	}
	if len(sd.EncapContentInfo.EContent) == 0 {
		return time.Time{}, fmt.Errorf("timestamp token carries no content")
	}

	var info struct {
		Version        int
		Policy         asn1.ObjectIdentifier
		MessageImprint asn1.RawValue
		SerialNumber   *big.Int
		GenTime        time.Time `asn1:"generalized"` // nolint:misspell // the ASN.1 tag encoding/asn1 requires
	}
	if _, err := asn1.Unmarshal(sd.EncapContentInfo.EContent, &info); err != nil {
		return time.Time{}, err
	}
	return info.GenTime, nil
}

// Description renders the signer as one line: who, and by whose certificate.
func (s Signer) Description() string {
	var parts []string
	switch {
	case s.CommonName != "" && s.Organisation != "" && !strings.EqualFold(s.CommonName, s.Organisation):
		parts = append(parts, s.CommonName+" ("+s.Organisation+")")
	case s.CommonName != "":
		parts = append(parts, s.CommonName)
	case s.Organisation != "":
		parts = append(parts, s.Organisation)
	}
	if s.Issuer != "" {
		parts = append(parts, "certificate issued by "+s.Issuer)
	}
	return strings.Join(parts, ", ")
}
