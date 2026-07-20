package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"
	"time"
)

// testCA is a self-signed CA used as the manager's trust bundle in tests.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newTestCA(t *testing.T, cn string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key gen: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("ca cert create: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ca cert parse: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testCA{cert: cert, key: key, pool: pool}
}

// issueLeaf signs a leaf certificate with the given SPIFFE URI SAN using
// this CA.
func (ca *testCA) issueLeaf(t *testing.T, spiffeURI string, serial int64) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key gen: %v", err)
	}
	u, err := url.Parse(spiffeURI)
	if err != nil {
		t.Fatalf("parse spiffe uri: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "aegisswarm-agent"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		URIs:         []*url.URL{u},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("leaf cert create: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("leaf cert parse: %v", err)
	}
	return cert
}

func newSelfSignedLeaf(t *testing.T, spiffeURI string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key gen: %v", err)
	}
	u, err := url.Parse(spiffeURI)
	if err != nil {
		t.Fatalf("parse spiffe uri: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      pkix.Name{CommonName: "self-signed-impostor"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		URIs:         []*url.URL{u},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("self-signed cert create: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("self-signed cert parse: %v", err)
	}
	return cert
}

// TestValidatePeer_AcceptsValidlySignedCertificate proves the positive
// case: a leaf certificate genuinely signed by a CA in the trust bundle,
// with a correct spiffe:// URI SAN in the expected trust domain, validates.
func TestValidatePeer_AcceptsValidlySignedCertificate(t *testing.T) {
	ca := newTestCA(t, "aegisswarm-test-root")
	mgr, err := NewSPIFFEManager(context.Background(), "agent-alpha", ca.pool)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}

	leaf := ca.issueLeaf(t, "spiffe://"+SVIDAudience+"/aegisswarm/agent/peer-1", 2)

	if err := mgr.ValidatePeer(leaf); err != nil {
		t.Fatalf("expected a validly CA-signed certificate with correct SPIFFE URI to be accepted, got: %v", err)
	}
}

// TestValidatePeer_RejectsSelfSignedCertificateWithCorrectURIText proves
// the core security property: a certificate whose URI SAN text is exactly
// right, but which is NOT signed by any CA in the trust bundle (here,
// self-signed — an attacker minting their own "identity"), is rejected.
// This is precisely the class of forgery the previous string-prefix
// comparison could not catch, because it never looked at a certificate or
// any signature at all.
func TestValidatePeer_RejectsSelfSignedCertificateWithCorrectURIText(t *testing.T) {
	ca := newTestCA(t, "aegisswarm-test-root")
	mgr, err := NewSPIFFEManager(context.Background(), "agent-alpha", ca.pool)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}

	// Correct-looking SPIFFE URI text, but self-signed — not chained to
	// the trust bundle's CA at all.
	forged := newSelfSignedLeaf(t, "spiffe://"+SVIDAudience+"/aegisswarm/agent/peer-1")

	if err := mgr.ValidatePeer(forged); err == nil {
		t.Fatal("SECURITY FAILURE: a self-signed certificate with correct URI text but no valid CA chain was accepted")
	}
}

// TestValidatePeer_RejectsWrongCACertificate proves that a certificate
// signed by a real CA — just not the one in this manager's trust bundle —
// is rejected. This simulates an attacker who controls their own CA and
// mints certificates with the right-looking SPIFFE URI.
func TestValidatePeer_RejectsWrongCACertificate(t *testing.T) {
	trustedCA := newTestCA(t, "aegisswarm-trusted-root")
	attackerCA := newTestCA(t, "attacker-controlled-root")

	mgr, err := NewSPIFFEManager(context.Background(), "agent-alpha", trustedCA.pool)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}

	forged := attackerCA.issueLeaf(t, "spiffe://"+SVIDAudience+"/aegisswarm/agent/peer-1", 3)

	if err := mgr.ValidatePeer(forged); err == nil {
		t.Fatal("SECURITY FAILURE: a certificate signed by an untrusted CA was accepted")
	}
}

// TestValidatePeer_RejectsWrongTrustDomain proves that even a validly
// CA-signed certificate is rejected if its SPIFFE URI names a different
// trust domain than expected.
func TestValidatePeer_RejectsWrongTrustDomain(t *testing.T) {
	ca := newTestCA(t, "aegisswarm-test-root")
	mgr, err := NewSPIFFEManager(context.Background(), "agent-alpha", ca.pool)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}

	leaf := ca.issueLeaf(t, "spiffe://attacker.example.com/aegisswarm/agent/peer-1", 4)

	if err := mgr.ValidatePeer(leaf); err == nil {
		t.Fatal("SECURITY FAILURE: a certificate for a foreign trust domain was accepted")
	}
}

// TestValidatePeer_FailsClosedWithNoTrustBundle proves that a manager
// constructed without a trust bundle rejects every peer, rather than
// falling back to a weaker (or no) check.
func TestValidatePeer_FailsClosedWithNoTrustBundle(t *testing.T) {
	mgr, err := NewSPIFFEManager(context.Background(), "agent-alpha", nil)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	ca := newTestCA(t, "aegisswarm-test-root")
	leaf := ca.issueLeaf(t, "spiffe://"+SVIDAudience+"/aegisswarm/agent/peer-1", 5)

	if err := mgr.ValidatePeer(leaf); err == nil {
		t.Fatal("SECURITY FAILURE: a peer validated successfully with no trust bundle configured at all")
	}
}

// TestValidatePeer_RejectsStringOnlyImpostor is a direct regression test
// against the original vulnerability: the old implementation accepted any
// caller-supplied string with the right prefix, with no certificate
// involved whatsoever. Passing nil now must fail, and there is no longer
// any code path that accepts a bare string as a peer identity.
func TestValidatePeer_RejectsNilCertificate(t *testing.T) {
	ca := newTestCA(t, "aegisswarm-test-root")
	mgr, err := NewSPIFFEManager(context.Background(), "agent-alpha", ca.pool)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	if err := mgr.ValidatePeer(nil); err == nil {
		t.Fatal("SECURITY FAILURE: a nil peer certificate was accepted")
	}
}
