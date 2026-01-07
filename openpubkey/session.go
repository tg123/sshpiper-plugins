package main

import "github.com/tg123/sshpiper-plugins/internal/pluginutil"

type sessionstore interface {
	GetSecret(session string) ([]byte, error)
	SetSecret(session string, secret []byte) error

	GetNonce(session string) (nonce []byte, err error)
	SetNonce(session string, nonce []byte) error

	GetUpstream(session string) (upstream string, err error)
	SetUpstream(session string, upstream string) error

	SetSshError(session string, err string) error
	GetSshError(session string) (err *string)

	DeleteSession(session string, keeperr bool) error
}

var _ sessionstore = (*sessionstoreMemory)(nil)

type sessionstoreMemory struct{ store *pluginutil.SessionStore }

func newSessionstoreMemory() (*sessionstoreMemory, error) {
	return &sessionstoreMemory{store: pluginutil.NewSessionStore()}, nil
}

func (s *sessionstoreMemory) GetNonce(session string) ([]byte, error) {
	return s.store.GetBytes(session, "nonce"), nil
}

func (s *sessionstoreMemory) SetNonce(session string, nonce []byte) error {
	s.store.SetBytes(session, "nonce", nonce)
	return nil
}

func (s *sessionstoreMemory) GetSecret(session string) ([]byte, error) {
	return s.store.GetBytes(session, "secret"), nil
}

func (s *sessionstoreMemory) SetSecret(session string, secret []byte) error {
	s.store.SetBytes(session, "secret", secret)
	return nil
}

func (s *sessionstoreMemory) GetUpstream(session string) (string, error) {
	upstream, ok := s.store.GetString(session, "upstream")
	if !ok {
		return "", nil
	}
	return upstream, nil
}

func (s *sessionstoreMemory) SetUpstream(session string, upstream string) error {
	s.store.SetString(session, "upstream", upstream)
	return nil
}

func (s *sessionstoreMemory) SetSshError(session string, err string) error {
	s.store.SetValue(session, "ssherror", &err)
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
