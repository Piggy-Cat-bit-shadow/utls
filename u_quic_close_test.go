package tls

import (
	"context"
	"testing"
	"time"
)

// closeQUICWithin runs Close in the background and fails the test if it does
// not return, so a Close that waits forever on the handshake goroutine shows up
// as a test failure instead of hanging the suite.
func closeQUICWithin(t *testing.T, close func() error, timeout time.Duration) error {
	t.Helper()

	done := make(chan error, 1)
	go func() { done <- close() }()
	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		t.Fatalf("Close did not return within %v; the handshake goroutine did not exit", timeout)
		return nil
	}
}

// TestUQUICConnCloseReportsHandshakeErrorOnce covers the upstream
// "keep in sync of UQUICConn and QUICConn" behaviour: a handshake error is
// surfaced through NextEvent exactly once instead of being dropped together
// with the event queue, and Close cancels the handshake and waits for the
// handshake goroutine to exit without deadlocking.
func TestUQUICConnCloseReportsHandshakeErrorOnce(t *testing.T) {
	config := testConfig.Clone()
	config.MinVersion = VersionTLS13
	config.MaxVersion = VersionTLS13

	q := UQUICClient(&QUICConfig{TLSConfig: config}, HelloFirefox_148)
	q.SetTransportParameters(nil)
	if err := q.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	closeErr := closeQUICWithin(t, q.Close, 30*time.Second)
	if closeErr == nil {
		t.Fatal("Close after a cancelled handshake returned nil, want the handshake error")
	}

	var errorEvents int
	for i := 0; i < 8; i++ {
		event := q.NextEvent()
		if event.Kind == QUICErrorEvent {
			errorEvents++
			if event.Err == nil {
				t.Fatal("QUICErrorEvent carries a nil error")
			}
		}
		if event.Kind == QUICNoEvent {
			break
		}
	}
	if errorEvents != 1 {
		t.Fatalf("got %d QUICErrorEvent, want exactly 1", errorEvents)
	}

	// The handshake goroutine has already exited, so a second Close must
	// return immediately rather than block on the closed channels.
	_ = closeQUICWithin(t, q.Close, 30*time.Second)
}
