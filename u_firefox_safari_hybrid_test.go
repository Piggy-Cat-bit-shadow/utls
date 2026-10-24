package tls

import (
	"bytes"
	"net"
	"testing"

	"github.com/metacubex/utls/mlkem"
)

// The Firefox 148 / Safari 26.3 hybrid key share is the reason this fork
// carries a custom hello commit. These tests keep an executable check on the
// three properties that matter for a REALITY-style peer: the presets are the
// ones selected by *Auto, the hybrid group is advertised on the wire with a
// real key share, and the handshake actually completes over the hybrid group.

func TestFirefoxSafariAutoPresetsSelectHybridLine(t *testing.T) {
	if HelloFirefox_Auto.Client != helloFirefox || HelloFirefox_Auto.Version != "148" {
		t.Fatalf("HelloFirefox_Auto = %v, want firefox-148", HelloFirefox_Auto)
	}
	if HelloSafari_Auto.Client != helloSafari || HelloSafari_Auto.Version != "26.3" {
		t.Fatalf("HelloSafari_Auto = %v, want safari-26.3", HelloSafari_Auto)
	}

	// The legacy presets must stay resolvable and must not advertise the
	// hybrid group, so the assertions above cannot silently pass through a
	// fallback to the older hello.
	for _, id := range []ClientHelloID{HelloFirefox_120, HelloSafari_16_0} {
		spec, err := UTLSIdToSpec(id)
		if err != nil {
			t.Fatalf("UTLSIdToSpec(%s): %v", id.Str(), err)
		}
		for _, ext := range spec.Extensions {
			curves, ok := ext.(*SupportedCurvesExtension)
			if !ok {
				continue
			}
			for _, curve := range curves.Curves {
				if curve == X25519MLKEM768 {
					t.Fatalf("%s unexpectedly advertises X25519MLKEM768", id.Str())
				}
			}
		}
	}
}

func hybridKeyShareFromWire(t *testing.T, id ClientHelloID) (curves []CurveID, hybrid []byte, shares []keyShare) {
	t.Helper()

	uconn := UClient(&net.TCPConn{}, &Config{
		ServerName: "example.com",
		Rand:       &incrementingSource{},
	}, id)
	if err := uconn.BuildHandshakeState(); err != nil {
		t.Fatalf("%s: BuildHandshakeState: %v", id.Str(), err)
	}

	raw := uconn.HandshakeState.Hello.Raw
	if len(raw) < 5 || raw[0] != typeClientHello {
		t.Fatalf("%s: unexpected ClientHello framing: %x", id.Str(), raw)
	}

	var hello clientHelloMsg
	if !hello.unmarshal(raw) {
		t.Fatalf("%s: failed to parse the marshalled ClientHello", id.Str())
	}
	for _, ks := range hello.keyShares {
		if ks.group == X25519MLKEM768 {
			hybrid = ks.data
		}
	}
	return hello.supportedCurves, hybrid, hello.keyShares
}

func TestFirefox148Safari263HybridKeyShareOnWire(t *testing.T) {
	wantHybridLen := mlkem.EncapsulationKeySize768 + x25519PublicKeySize

	for _, id := range []ClientHelloID{HelloFirefox_148, HelloSafari_26_3} {
		t.Run(id.Str(), func(t *testing.T) {
			curves, hybrid, shares := hybridKeyShareFromWire(t, id)

			found := false
			for _, curve := range curves {
				if curve == X25519MLKEM768 {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("%s: supported_groups does not advertise X25519MLKEM768", id.Str())
			}
			if len(hybrid) != wantHybridLen {
				t.Fatalf("%s: hybrid key share is %d bytes, want %d (ML-KEM-768 encapsulation key + X25519 share)",
					id.Str(), len(hybrid), wantHybridLen)
			}

			// The trailing X25519 element of the hybrid share must belong to
			// the same connection state as the classical X25519 share.
			var classical []byte
			for _, ks := range shares {
				if ks.group == X25519 {
					classical = ks.data
				}
			}
			if len(classical) != x25519PublicKeySize {
				t.Fatalf("%s: X25519 key share is %d bytes, want %d", id.Str(), len(classical), x25519PublicKeySize)
			}
			trailing := hybrid[len(hybrid)-x25519PublicKeySize:]
			if !bytes.Equal(trailing, classical) && id == HelloFirefox_148 {
				t.Fatalf("%s: expected the classical key share to be reused inside the hybrid share", id.Str())
			}
			if bytes.Equal(trailing, classical) && id == HelloSafari_26_3 {
				t.Fatalf("%s: expected an independent classical key share", id.Str())
			}
		})
	}
}

func TestFirefox148Safari263HybridHandshake(t *testing.T) {
	for _, id := range []ClientHelloID{HelloFirefox_148, HelloSafari_26_3} {
		t.Run(id.Str(), func(t *testing.T) {
			clientConfig := testConfig.Clone()
			clientConfig.ServerName = "example.com"
			clientConfig.Rand = nil // hybrid key generation needs real randomness

			serverConfig := testConfig.Clone()
			serverConfig.Rand = nil
			serverConfig.CurvePreferences = []CurveID{X25519MLKEM768}

			c, s := localPipe(t)
			type result struct {
				state ConnectionState
				err   error
			}
			clientDone := make(chan result, 1)
			go func() {
				client := UClient(c, clientConfig, id)
				if err := client.Handshake(); err != nil {
					clientDone <- result{err: err}
					c.Close()
					return
				}
				state := client.ConnectionState()
				client.Close()
				clientDone <- result{state: state}
			}()

			server := Server(s, serverConfig)
			serverErr := server.Handshake()
			var serverState ConnectionState
			if serverErr == nil {
				serverState = server.ConnectionState()
				server.Close()
			} else {
				s.Close()
			}

			got := <-clientDone
			if serverErr != nil {
				t.Fatalf("server handshake: %v", serverErr)
			}
			if got.err != nil {
				t.Fatalf("client handshake: %v", got.err)
			}
			if serverState.CurveID != X25519MLKEM768 {
				t.Fatalf("server negotiated curve %v, want X25519MLKEM768", serverState.CurveID)
			}
			if got.state.CurveID != X25519MLKEM768 {
				t.Fatalf("client negotiated curve %v, want X25519MLKEM768", got.state.CurveID)
			}
			if got.state.Version != VersionTLS13 {
				t.Fatalf("client negotiated version %#x, want TLS 1.3", got.state.Version)
			}
		})
	}
}
