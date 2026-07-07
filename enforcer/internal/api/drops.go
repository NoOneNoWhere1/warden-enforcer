package api

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/NoOneNoWhere1/warden-enforcer/enforcer/internal/breachevent"
	"github.com/NoOneNoWhere1/warden-enforcer/enforcer/internal/canonical"
	"github.com/NoOneNoWhere1/warden-enforcer/enforcer/internal/outbox"
	"github.com/NoOneNoWhere1/warden-enforcer/enforcer/internal/sandbox"
)

// eventsCap bounds the per-session events slice (ring behavior: oldest
// evicted, eviction counted). The bounded drops channel does not bound this
// slice — this does.
const eventsCap = 256

// Admission control (E3.3, council S2): a horizontal scan must not turn the
// signer into a CPU sink or flood the spool. Tokens refill per second up to
// the burst capacity; a drop arriving with no token is counted as lost.
// ponytail: fixed rates; make them credential-driven if a deployment needs it.
const (
	bucketBurst     = 20.0
	bucketPerSecond = 5.0
)

type tokenBucket struct {
	tokens float64
	last   time.Time
}

// ConsumeDrops is the single consumer of packet facts from the sandbox
// nflog listeners (E3.2 / council B2): the only code that turns a Drop into
// a signed BreachEvent, and it does so under the one AppState lock — the
// signing key never enters a netns goroutine. The durable spool append
// happens here, outside the lock (this goroutine is the spool's only
// writer), and always BEFORE any Rekor attempt sees the entry. Run it as a
// goroutine from main; it exits when the channel closes.
func (s *AppState) ConsumeDrops(drops <-chan sandbox.Drop) {
	for d := range drops {
		entry, ok := s.recordDrop(d)
		if !ok || s.Outbox == nil {
			continue
		}
		if err := s.Outbox.Append(*entry); err != nil {
			// The event still serves from the API ring; the durable copy is
			// what was lost — count it visibly rather than crash the consumer.
			s.mu.Lock()
			s.addLossLocked(d.SessionID, 1)
			s.mu.Unlock()
			continue
		}
		if s.OutboxKick != nil {
			select {
			case s.OutboxKick <- struct{}{}:
			default:
			}
		}
	}
}

// recordDrop admits, signs, and stores one drop under the AppState lock,
// returning the self-contained spool entry (event + second signature +
// public key, per council B3 — replayable after key rotation without a
// private key).
func (s *AppState) recordDrop(d sandbox.Drop) (*outbox.Entry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cred, ok := s.Sessions[d.SessionID]
	if !ok {
		return nil, false // session destroyed between the kernel log and here
	}

	if !s.admitLocked(d.SessionID) {
		s.addLossLocked(d.SessionID, 1)
		return nil, false
	}

	violation := fmt.Sprintf("attempted connection to %s:%d", d.DstIP, d.DstPort)
	if d.DstPort == 0 {
		violation = fmt.Sprintf("attempted connection to %s (%s)", d.DstIP, d.Proto)
	}

	ev := breachevent.New(d.SessionID, cred.AgentID, violation, s.ActiveKey.KeyID())
	if err := ev.Sign(s.ActiveKey.SigningKey()); err != nil {
		return nil, false // never store an unsigned event; Sign only fails on marshal errors
	}

	reduced, err := canonical.ToCanonicalBytes(ev.RekorPayload())
	if err != nil {
		return nil, false
	}
	secondSig := ed25519.Sign(s.ActiveKey.SigningKey(), reduced)
	pkix, err := x509.MarshalPKIXPublicKey(s.ActiveKey.VerifyingKey())
	if err != nil {
		return nil, false
	}
	sum := sha256.Sum256(reduced)

	evs := s.Events[d.SessionID]
	if len(evs) >= eventsCap {
		// ponytail: reslice+append reallocates the 256-slot array once per
		// event at cap — fine at this size, ring-index it if cap ever grows.
		evs = evs[1:]
		s.addLossLocked(d.SessionID, 1)
	}
	s.Events[d.SessionID] = append(evs, *ev)

	return &outbox.Entry{
		Event:         *ev,
		SecondSig:     base64.RawURLEncoding.EncodeToString(secondSig),
		PublicKeyPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkix})),
		PayloadSHA256: hex.EncodeToString(sum[:]),
	}, true
}

// admitLocked applies the per-session token bucket. Caller holds mu.
func (s *AppState) admitLocked(sessionID string) bool {
	now := time.Now()
	if s.Now != nil {
		now = s.Now()
	}
	if s.buckets == nil {
		s.buckets = map[string]*tokenBucket{}
	}
	b, ok := s.buckets[sessionID]
	if !ok {
		b = &tokenBucket{tokens: bucketBurst, last: now}
		s.buckets[sessionID] = b
	}
	b.tokens = min(bucketBurst, b.tokens+now.Sub(b.last).Seconds()*bucketPerSecond)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// addLossLocked increments the session's visible loss counter (ring
// evictions, rate-limited drops, failed spool appends; the sandbox layer
// separately counts channel overflow). Caller holds mu.
func (s *AppState) addLossLocked(sessionID string, n uint64) {
	if s.EventLosses == nil {
		s.EventLosses = map[string]uint64{}
	}
	s.EventLosses[sessionID] += n
}
