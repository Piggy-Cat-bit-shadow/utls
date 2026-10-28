package tls

import (
	"encoding/binary"
	"testing"
)

// clientHelloExtensionBodies splits a marshalled ClientHello into its extension
// bodies, keyed by extension type. A test can therefore distinguish "this
// extension is in the ClientHelloInner body" from "this extension was moved into
// the ECH outer_extensions list".
func clientHelloExtensionBodies(t *testing.T, raw []byte) map[uint16][]byte {
	t.Helper()

	// handshake type + uint24 length, legacy_version, random
	if len(raw) < 4+2+32+1 {
		t.Fatalf("ClientHello is %d bytes, too short to parse", len(raw))
	}
	p := 4 + 2 + 32
	p += 1 + int(raw[p]) // session_id
	if p+2 > len(raw) {
		t.Fatalf("ClientHello ends inside the cipher_suites length prefix (%d/%d)", p, len(raw))
	}
	p += 2 + int(binary.BigEndian.Uint16(raw[p:])) // cipher_suites
	if p+1 > len(raw) {
		t.Fatalf("ClientHello ends inside the compression_methods length prefix (%d/%d)", p, len(raw))
	}
	p += 1 + int(raw[p]) // compression_methods
	if p == len(raw) {
		return nil
	}
	if p+2 > len(raw) {
		t.Fatalf("ClientHello ends inside the extensions length prefix (%d/%d)", p, len(raw))
	}
	extTotal := int(binary.BigEndian.Uint16(raw[p:]))
	p += 2
	if p+extTotal != len(raw) {
		t.Fatalf("extensions block declares %d bytes, %d remain", extTotal, len(raw)-p)
	}

	bodies := make(map[uint16][]byte)
	for p < len(raw) {
		if p+4 > len(raw) {
			t.Fatalf("ClientHello ends inside an extension header (%d/%d)", p, len(raw))
		}
		extType := binary.BigEndian.Uint16(raw[p:])
		extLen := int(binary.BigEndian.Uint16(raw[p+2:]))
		p += 4
		if p+extLen > len(raw) {
			t.Fatalf("extension %#04x declares %d bytes, %d remain", extType, extLen, len(raw)-p)
		}
		if _, seen := bodies[extType]; seen {
			t.Fatalf("extension %#04x appears twice in one ClientHello", extType)
		}
		bodies[extType] = raw[p : p+extLen]
		p += extLen
	}
	return bodies
}

// echOuterExtensionList decodes the type list carried by the ECH
// outer_extensions extension (draft-ietf-tls-esni).
func echOuterExtensionList(t *testing.T, body []byte) []uint16 {
	t.Helper()

	if len(body) < 1 {
		t.Fatalf("outer_extensions body is empty")
	}
	listLen := int(body[0])
	if len(body) != 1+listLen {
		t.Fatalf("outer_extensions body is %d bytes, its length byte says %d", len(body), listLen)
	}
	if listLen%2 != 0 {
		t.Fatalf("outer_extensions list is %d bytes, not a whole number of uint16s", listLen)
	}
	list := make([]uint16, 0, listLen/2)
	for i := 1; i < len(body); i += 2 {
		list = append(list, binary.BigEndian.Uint16(body[i:]))
	}
	return list
}

func containsExtension(list []uint16, want uint16) bool {
	for _, entry := range list {
		if entry == want {
			return true
		}
	}
	return false
}

// TestECHCompressesALPNOnlyForAStandardClientHello pins upstream a6a364af in the
// shape this fork needs it.
//
// The ECH spec allows the ClientHelloInner to carry a different ALPN list from
// the outer ClientHello, and a custom ClientHello that reorders its outer
// extensions may use exactly that. Compressing ALPN - listing it in
// outer_extensions instead of sending it in the inner body - is only correct
// when the two lists are the same, which is the standard-ClientHello case. This
// fork already applied that condition to supported_versions for the same reason
// (uTLS section marker in clientHelloMsg.marshalMsgReorderOuterExts); the ALPN
// branch used to be disabled unconditionally, so a custom hello could never
// carry a real inner ALPN.
func TestECHCompressesALPNOnlyForAStandardClientHello(t *testing.T) {
	newHello := func() *clientHelloMsg {
		return &clientHelloMsg{
			vers:                         VersionTLS12,
			random:                       make([]byte, 32),
			sessionId:                    []byte("0123456789abcdef0123456789abcdef"),
			cipherSuites:                 []uint16{TLS_AES_128_GCM_SHA256},
			compressionMethods:           []byte{0},
			serverName:                   "inner.example",
			supportedCurves:              []CurveID{X25519},
			supportedVersions:            []uint16{VersionTLS13},
			supportedSignatureAlgorithms: []SignatureScheme{PSSWithSHA256},
			keyShares:                    []keyShare{{group: X25519, data: make([]byte, 32)}},
			pskModes:                     []byte{1},
			alpnProtocols:                []string{"h2", "http/1.1"},
		}
	}

	t.Run("standard ClientHello compresses ALPN", func(t *testing.T) {
		raw, err := newHello().marshalMsgReorderOuterExts(true, nil)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		bodies := clientHelloExtensionBodies(t, raw)

		if _, ok := bodies[extensionALPN]; ok {
			t.Error("the inner ClientHello carries its own ALPN; a standard hello must compress it into outer_extensions")
		}
		outer, ok := bodies[extensionECHOuterExtensions]
		if !ok {
			t.Fatal("the inner ClientHello has no outer_extensions extension")
		}
		if !containsExtension(echOuterExtensionList(t, outer), extensionALPN) {
			t.Errorf("outer_extensions does not list ALPN: %v", echOuterExtensionList(t, outer))
		}
	})

	t.Run("custom ClientHello keeps a real inner ALPN", func(t *testing.T) {
		// A custom hello that orders its outer extensions, which is the case the
		// fork's reordering support exists for.
		outerExts := []uint16{extensionALPN, extensionSupportedCurves, extensionSignatureAlgorithms, extensionKeyShare, extensionPSKModes}
		raw, err := newHello().marshalMsgReorderOuterExts(true, outerExts)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		bodies := clientHelloExtensionBodies(t, raw)

		alpn, ok := bodies[extensionALPN]
		if !ok {
			t.Fatal("the inner ClientHello has no ALPN extension; a custom hello must carry its own list so inner and outer can differ")
		}
		// The body must be the real ALPN extension: uint16 list length, then
		// uint8-prefixed protocol names. Re-encoding the same list is the check
		// that it is not a placeholder.
		want := []byte{0x00, 0x0c, 0x02, 'h', '2', 0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'}
		if string(alpn) != string(want) {
			t.Fatalf("inner ALPN is % x, want % x", alpn, want)
		}
		if outer, ok := bodies[extensionECHOuterExtensions]; ok {
			if containsExtension(echOuterExtensionList(t, outer), extensionALPN) {
				t.Error("outer_extensions lists ALPN while the inner hello also carries it")
			}
		}
	})

	t.Run("non-ECH ClientHello carries ALPN in the body", func(t *testing.T) {
		raw, err := newHello().marshalMsgReorderOuterExts(false, nil)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		bodies := clientHelloExtensionBodies(t, raw)
		if _, ok := bodies[extensionALPN]; !ok {
			t.Fatal("a ClientHello without ECH inner mode must carry its ALPN in the body")
		}
		if _, ok := bodies[extensionECHOuterExtensions]; ok {
			t.Error("a ClientHello without ECH inner mode must not carry outer_extensions")
		}
	})
}
