package tls

import "crypto/x509"

// AesgcmPreferred reports whether the first known cipher in the peer's
// preference list is an AES-GCM cipher.
//
// Upstream renamed the unexported helper this wrapper used to call and added
// a hardware-support gate to the replacement (isAESGCMPreferred). The exported
// helper keeps its original, gate-free behaviour.
func AesgcmPreferred(ciphers []uint16) bool {
	for _, cID := range ciphers {
		if c := cipherSuiteByID(cID); c != nil {
			return aesgcmCiphers[cID]
		}
		if c := cipherSuiteTLS13ByID(cID); c != nil {
			return aesgcmCiphers[cID]
		}
	}
	return false
}

func (c *Conn) PeerCertificates() []*x509.Certificate {
	return c.peerCertificates
}

func HasAESGCMHardwareSupport() bool {
	return hasAESGCMHardwareSupport
}
