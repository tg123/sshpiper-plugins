package main

import "github.com/tg123/sshpiper-plugins/internal/pluginutil"

type sessionstore interface {
	GetSecret(session string) ([]byte, error)
	SetSecret(session string, secret []byte) error

	GetUpstream(session string) (upstream *upstreamConfig, err error)
	SetUpstream(session string, upstream *upstreamConfig) error

	SetSshError(session string, err string) error
	GetSshError(session string) (err *string)

	DeleteSession(session string, keeperr bool) error
}

type sessionstoreMemory struct{ store *pluginutil.SessionStore }

func newSessionstoreMemory() (*sessionstoreMemory, error) {
	return &sessionstoreMemory{store: pluginutil.NewSessionStore()}, nil
}

func (s *sessionstoreMemory) GetSecret(session string) ([]byte, error) {
	return s.store.GetBytes(session, "secret"), nil
}

func (s *sessionstoreMemory) SetSecret(session string, secret []byte) error {
	s.store.SetBytes(session, "secret", secret)
	return nil
}

func (s *sessionstoreMemory) GetUpstream(session string) (*upstreamConfig, error) {
	upstream, ok := s.store.GetValue(session, "upstream")
	if !ok {
		return nil, nil
	}

	if u, ok := upstream.(*upstreamConfig); ok {
		return u, nil
	}

	return nil, nil
}

func (s *sessionstoreMemory) SetUpstream(session string, upstream *upstreamConfig) error {
	s.store.SetValue(session, "upstream", upstream)
	return nil
}

func (s *sessionstoreMemory) SetSshError(session string, err string) error {
	e := err
	s.store.SetValue(session, "ssherror", &e)
	return nil
}

func (s *sessionstoreMemory) GetSshError(session string) (err *string) {
	v, ok := s.store.GetValue(session, "ssherror")
	if !ok {
		return nil
	}

	if e, ok := v.(*string); ok {
		return e
	}

	return nil
}

func (s *sessionstoreMemory) DeleteSession(session string, keeperr bool) error {
	s.store.Delete(session, "secret", "upstream")
	if !keeperr {
		s.store.Delete(session, "ssherror")
	}
	return nil
}
