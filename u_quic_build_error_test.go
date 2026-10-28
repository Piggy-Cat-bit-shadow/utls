package tls

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestQUICStartReportsABuildHandshakeStateError pins upstream 72aa2193 through
// the path this fork actually ships.
//
// A QUIC client whose ClientHello cannot be built must report that error and
// must still run the QUIC handshake cleanup. Before the fix, handshakeContext
// returned the BuildHandshakeState error BEFORE the block that closes
// quic.blockedc and quic.signalc, so UQUICConn.Start blocked forever on
// blockedc and Close could never collect the handshake goroutine. A hang is not
// an error report, and this test fails on the hang rather than waiting for it.
func TestQUICStartReportsABuildHandshakeStateError(t *testing.T) {
	config := testConfig.Clone()
	config.MinVersion = VersionTLS13
	config.MaxVersion = VersionTLS13

	// An unknown ClientHelloID is rejected by applyPresetByID, which is called
	// from BuildHandshakeState - exactly the error path under test. Nothing is
	// sent, so the test needs no network.
	unknown := ClientHelloID{Client: "unknown-client", Version: "0"}
	q := UQUICClient(&QUICConfig{TLSConfig: config}, unknown)

	type startResult struct{ err error }
	done := make(chan startResult, 1)
	go func() { done <- startResult{q.Start(context.Background())} }()

	var startErr error
	select {
	case result := <-done:
		startErr = result.err
	case <-time.After(30 * time.Second):
		t.Fatal("Start did not return after a BuildHandshakeState failure; the QUIC handshake cleanup was skipped")
	}
	if startErr == nil {
		t.Fatal("Start returned nil after a BuildHandshakeState failure")
	}
	if !strings.Contains(startErr.Error(), "unknown ClientHelloID") {
		t.Fatalf("Start returned %q, want the BuildHandshakeState error", startErr)
	}
	if strings.Contains(startErr.Error(), "internal error") {
		t.Fatalf("Start returned %q, which means the cleanup rewrote the cause", startErr)
	}

	// The same error has to be observable through the event API, exactly once,
	// because that is how a QUIC implementation learns the handshake failed.
	event := q.NextEvent()
	if event.Kind != QUICErrorEvent {
		t.Fatalf("first event is %v, want QUICErrorEvent", event.Kind)
	}
	if event.Err == nil {
		t.Fatal("QUICErrorEvent carries a nil error")
	}
	if !strings.Contains(event.Err.Error(), "unknown ClientHelloID") {
		t.Fatalf("QUICErrorEvent carries %q, want the BuildHandshakeState error", event.Err)
	}
	if next := q.NextEvent(); next.Kind != QUICNoEvent {
		t.Fatalf("second event is %v, want QUICNoEvent: the error must be reported once", next.Kind)
	}

	// Close must not block: the handshake goroutine has already exited.
	_ = closeQUICWithin(t, q.Close, 30*time.Second)
}
