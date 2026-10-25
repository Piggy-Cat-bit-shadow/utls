package tls

import (
	"bytes"
	"context"
	"testing"
	"time"
)

// quic_transport_parameters carries its parameters as (id, value) pairs, so the
// ClientHello extension body is exactly the blob the QUIC layer supplied.
func quicClientHelloTransportParameters(t *testing.T, handshake []byte) []byte {
	t.Helper()

	if len(handshake) < 4 {
		t.Fatalf("handshake message is %d bytes, too short for a ClientHello", len(handshake))
	}
	body := handshake[4:]
	if len(body) < 2+32+1 {
		t.Fatalf("ClientHello body is %d bytes, too short", len(body))
	}
	offset := 2 + 32
	sessionIDLen := int(body[offset])
	offset += 1 + sessionIDLen
	if offset+2 > len(body) {
		t.Fatalf("ClientHello truncated before the cipher suites")
	}
	cipherSuitesLen := int(body[offset])<<8 | int(body[offset+1])
	offset += 2 + cipherSuitesLen
	if offset+1 > len(body) {
		t.Fatalf("ClientHello truncated before the compression methods")
	}
	compressionLen := int(body[offset])
	offset += 1 + compressionLen
	if offset+2 > len(body) {
		t.Fatalf("ClientHello truncated before the extensions")
	}
	extensionsLen := int(body[offset])<<8 | int(body[offset+1])
	offset += 2
	end := offset + extensionsLen
	if end > len(body) {
		t.Fatalf("ClientHello extensions are truncated: want %d bytes, have %d", extensionsLen, len(body)-offset)
	}

	for offset+4 <= end {
		extensionType := int(body[offset])<<8 | int(body[offset+1])
		extensionLen := int(body[offset+2])<<8 | int(body[offset+3])
		offset += 4
		if offset+extensionLen > end {
			t.Fatalf("extension %#x is truncated", extensionType)
		}
		if extensionType == int(extensionQUICTransportParameters) {
			return body[offset : offset+extensionLen]
		}
		offset += extensionLen
	}
	t.Fatal("quic_transport_parameters extension not found in the ClientHello")
	return nil
}

// TestUQUICPresetTransportParametersReachClientHello pins the path quic-go uses:
// it applies a ClientHelloSpec to a UQUICConn and then installs the transport
// parameters into that spec, because uTLS exposes no other way to fill a preset's
// quic_transport_parameters extension. ApplyPreset clones the spec, so without
// syncQUICTransportParameters the ClientHello would carry the preset's empty
// extension and a QUIC server would reject it (missing
// initial_source_connection_id).
func TestUQUICPresetTransportParametersReachClientHello(t *testing.T) {
	config := testConfig.Clone()
	config.MinVersion = VersionTLS13
	config.MaxVersion = VersionTLS13

	spec := &ClientHelloSpec{
		CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
		CompressionMethods: []uint8{compressionNone},
		Extensions: []TLSExtension{
			&SNIExtension{},
			&SupportedVersionsExtension{Versions: []uint16{VersionTLS13}},
			&KeyShareExtension{KeyShares: []KeyShare{{Group: X25519}}},
			&QUICTransportParametersExtension{},
		},
	}

	// initial_source_connection_id (0x0f) followed by initial_max_data (0x04).
	params := []byte{
		0x0f, 0x08, 1, 2, 3, 4, 5, 6, 7, 8,
		0x04, 0x02, 0x44, 0x00,
	}

	q := UQUICClient(&QUICConfig{TLSConfig: config}, HelloCustom)
	if err := q.ApplyPreset(spec); err != nil {
		t.Fatalf("ApplyPreset: %v", err)
	}
	q.SetTransportParameters(params)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := q.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	var handshake []byte
	for {
		event := q.NextEvent()
		if event.Kind == QUICNoEvent {
			break
		}
		if event.Kind == QUICWriteData {
			handshake = append(handshake, event.Data...)
		}
	}
	_ = q.Close()

	if len(handshake) == 0 {
		t.Fatal("no handshake data was produced")
	}
	got := quicClientHelloTransportParameters(t, handshake)
	if !bytes.Equal(got, params) {
		t.Fatalf("ClientHello quic_transport_parameters = %x, want %x", got, params)
	}
}
