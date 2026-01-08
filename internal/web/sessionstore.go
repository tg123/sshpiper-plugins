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
