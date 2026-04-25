package web

import (
	"time"

	"github.com/patrickmn/go-cache"
)

type SessionStore struct {
	store *cache.Cache
}

func NewSessionStore() *SessionStore {
	return &SessionStore{
		store: cache.New(1*time.Minute, 10*time.Minute),
	}
}

func key(session, suffix string) string {
	return session + "-" + suffix
}

func (s *SessionStore) SetBytes(session, suffix string, value []byte) {
	s.store.SetDefault(key(session, suffix), value)
}

func (s *SessionStore) GetBytes(session, suffix string) []byte {
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

func (s *SessionStore) SetString(session, suffix, value string) {
	s.store.SetDefault(key(session, suffix), value)
}

func (s *SessionStore) GetString(session, suffix string) (string, bool) {
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

func (s *SessionStore) SetValue(session, suffix string, value any) {
	s.store.SetDefault(key(session, suffix), value)
}

func (s *SessionStore) GetValue(session, suffix string) (any, bool) {
	v, found := s.store.Get(key(session, suffix))
	if !found {
		return nil, false
	}

	return v, true
}

func (s *SessionStore) Delete(session string, suffixes ...string) {
	for _, suffix := range suffixes {
		s.store.Delete(key(session, suffix))
	}
}

// Common session keys shared by plugins.
const (
	KeySecret   = "secret"
	KeyUpstream = "upstream"
	KeySshError = "ssherror"
)

// SetSecret stores a per-session secret payload.
func (s *SessionStore) SetSecret(session string, secret []byte) {
	s.SetBytes(session, KeySecret, secret)
}

// GetSecret retrieves a previously stored per-session secret payload.
func (s *SessionStore) GetSecret(session string) []byte {
	return s.GetBytes(session, KeySecret)
}

// SetSshError stores the latest ssh-side error message for a session.
// A pointer is stored so callers can distinguish "unset" (nil) from
// "explicitly empty" (non-nil pointer to "").
func (s *SessionStore) SetSshError(session, err string) {
	s.SetValue(session, KeySshError, &err)
}

// GetSshError returns the latest ssh-side error message for a session,
// or nil if none was set.
func (s *SessionStore) GetSshError(session string) *string {
	v, ok := s.GetValue(session, KeySshError)
	if !ok {
		return nil
	}

	if e, ok := v.(*string); ok {
		return e
	}

	return nil
}

// Reset clears the secret, upstream and any extra session keys provided.
// When keeperr is false the ssh error key is also cleared.
func (s *SessionStore) Reset(session string, keeperr bool, extraKeys ...string) {
	keys := append([]string{KeySecret, KeyUpstream}, extraKeys...)
	s.Delete(session, keys...)
	if !keeperr {
		s.Delete(session, KeySshError)
	}
}
