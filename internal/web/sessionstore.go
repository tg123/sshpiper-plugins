package web

import (
	"time"

	"github.com/patrickmn/go-cache"
)

// Common session keys shared by plugins.
const (
	KeySecret   = "secret"
	KeyUpstream = "upstream"
	KeySshError = "ssherror"
)

// SessionStore is the per-session key/value store used by plugins.
//
// The Upstream type parameter lets each plugin store its own upstream
// representation (e.g. a string or a typed config) without losing type
// safety, while the rest of the API stays untyped for generic blob/value
// storage.
type SessionStore[Upstream any] interface {
	SetBytes(session, suffix string, value []byte)
	GetBytes(session, suffix string) []byte

	SetString(session, suffix, value string)
	GetString(session, suffix string) (string, bool)

	SetValue(session, suffix string, value any)
	GetValue(session, suffix string) (any, bool)

	Delete(session string, suffixes ...string)

	SetSecret(session string, secret []byte)
	GetSecret(session string) []byte

	SetSshError(session, err string)
	GetSshError(session string) *string

	SetUpstream(session string, upstream Upstream)
	GetUpstream(session string) Upstream

	// Reset clears the secret, upstream and any extra session keys provided.
	// When keeperr is false the ssh error key is also cleared.
	Reset(session string, keeperr bool, extraKeys ...string)
}

// NewSessionStore returns the default in-memory SessionStore implementation.
func NewSessionStore[Upstream any]() SessionStore[Upstream] {
	return &memorySessionStore[Upstream]{
		store: cache.New(1*time.Minute, 10*time.Minute),
	}
}

type memorySessionStore[Upstream any] struct {
	store *cache.Cache
}

func key(session, suffix string) string {
	return session + "-" + suffix
}

func (s *memorySessionStore[Upstream]) SetBytes(session, suffix string, value []byte) {
	s.store.SetDefault(key(session, suffix), value)
}

func (s *memorySessionStore[Upstream]) GetBytes(session, suffix string) []byte {
	v, found := s.store.Get(key(session, suffix))
	if !found {
		return nil
	}

	b, ok := v.([]byte)
	if !ok {
		return nil
	}

	return b
}

func (s *memorySessionStore[Upstream]) SetString(session, suffix, value string) {
	s.store.SetDefault(key(session, suffix), value)
}

func (s *memorySessionStore[Upstream]) GetString(session, suffix string) (string, bool) {
	v, found := s.store.Get(key(session, suffix))
	if !found {
		return "", false
	}

	str, ok := v.(string)
	if !ok {
		return "", false
	}

	return str, true
}

func (s *memorySessionStore[Upstream]) SetValue(session, suffix string, value any) {
	s.store.SetDefault(key(session, suffix), value)
}

func (s *memorySessionStore[Upstream]) GetValue(session, suffix string) (any, bool) {
	v, found := s.store.Get(key(session, suffix))
	if !found {
		return nil, false
	}

	return v, true
}

func (s *memorySessionStore[Upstream]) Delete(session string, suffixes ...string) {
	for _, suffix := range suffixes {
		s.store.Delete(key(session, suffix))
	}
}

func (s *memorySessionStore[Upstream]) SetSecret(session string, secret []byte) {
	s.SetBytes(session, KeySecret, secret)
}

func (s *memorySessionStore[Upstream]) GetSecret(session string) []byte {
	return s.GetBytes(session, KeySecret)
}

// SetSshError stores the latest ssh-side error message for a session.
// A pointer is stored so callers can distinguish "unset" (nil) from
// "explicitly empty" (non-nil pointer to "").
func (s *memorySessionStore[Upstream]) SetSshError(session, err string) {
	s.SetValue(session, KeySshError, &err)
}

func (s *memorySessionStore[Upstream]) GetSshError(session string) *string {
	v, ok := s.GetValue(session, KeySshError)
	if !ok {
		return nil
	}

	if e, ok := v.(*string); ok {
		return e
	}

	return nil
}

func (s *memorySessionStore[Upstream]) SetUpstream(session string, upstream Upstream) {
	s.SetValue(session, KeyUpstream, upstream)
}

func (s *memorySessionStore[Upstream]) GetUpstream(session string) Upstream {
	var zero Upstream

	v, ok := s.GetValue(session, KeyUpstream)
	if !ok {
		return zero
	}

	if u, ok := v.(Upstream); ok {
		return u
	}

	return zero
}

func (s *memorySessionStore[Upstream]) Reset(session string, keeperr bool, extraKeys ...string) {
	keys := append([]string{KeySecret, KeyUpstream}, extraKeys...)
	s.Delete(session, keys...)
	if !keeperr {
		s.Delete(session, KeySshError)
	}
}
