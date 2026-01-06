package main

import (
	"crypto/subtle"
	"fmt"
	"strings"

	"github.com/tg123/sshpiper/libplugin"
	"github.com/tg123/sshpiper/libplugin/skel"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type skelpipeWrapper struct {
	pipe *pipeConfig
}

type skelpipeFromWrapper struct {
	skelpipeWrapper
}

type skelpipeFromPasswordWrapper struct {
	skelpipeFromWrapper
}

type skelpipeFromPublicKeyWrapper struct {
	skelpipeFromWrapper
}

type skelpipeToWrapper struct {
	skelpipeWrapper

	username string
}

type skelpipeToPasswordWrapper struct {
	skelpipeToWrapper
}

type skelpipeToPrivateKeyWrapper struct {
	skelpipeToWrapper
}

func (s *skelpipeWrapper) From() []skel.SkelPipeFrom {

	w := skelpipeFromWrapper{
		skelpipeWrapper: *s,
	}

	switch s.pipe.FromType {
	case authMapTypePassword:
		return []skel.SkelPipeFrom{&skelpipeFromPasswordWrapper{
			skelpipeFromWrapper: w,
		}}
	case authMapTypePrivateKey:
		return []skel.SkelPipeFrom{&skelpipeFromPublicKeyWrapper{
			skelpipeFromWrapper: w,
		}}

	default:
		return nil
	}
}

func (s *skelpipeToWrapper) User(conn libplugin.ConnMetadata) string {
	return s.username
}

func (s *skelpipeToWrapper) Host(conn libplugin.ConnMetadata) string {
	return s.pipe.UpstreamHost
}

func (s *skelpipeToWrapper) IgnoreHostKey(conn libplugin.ConnMetadata) bool {
	return s.pipe.IgnoreHostkey
}

func (s *skelpipeToWrapper) KnownHosts(conn libplugin.ConnMetadata) ([]byte, error) {
	data := strings.TrimSpace(s.pipe.KnownHosts.Data)

	if data == "" {
		return nil, nil
	}

	if pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(data)); err == nil {
		return []byte(knownhosts.Line([]string{s.pipe.UpstreamHost}, pub)), nil
	}

	if signer, err := ssh.ParsePrivateKey([]byte(data)); err == nil {
		return []byte(knownhosts.Line([]string{s.pipe.UpstreamHost}, signer.PublicKey())), nil
	}

	return []byte(data), nil
}

func (s *skelpipeFromWrapper) MatchConn(conn libplugin.ConnMetadata) (skel.SkelPipeTo, error) {

	switch s.pipe.ToType {
	case authMapTypePassword:
		return &skelpipeToPasswordWrapper{
			skelpipeToWrapper: skelpipeToWrapper{
				username:        s.pipe.MappedUsername,
				skelpipeWrapper: s.skelpipeWrapper,
			},
		}, nil
	case authMapTypePrivateKey:
		return &skelpipeToPrivateKeyWrapper{
			skelpipeToWrapper: skelpipeToWrapper{
				username:        s.pipe.MappedUsername,
				skelpipeWrapper: s.skelpipeWrapper,
			},
		}, nil
	}

	return nil, fmt.Errorf("unsupported authMapType %d", s.pipe.ToType)
}

func (s *skelpipeFromPasswordWrapper) TestPassword(conn libplugin.ConnMetadata, password []byte) (bool, error) {

	if s.pipe.FromPassword == "" {
		// ignore password
		return true, nil
	}

	return subtle.ConstantTimeCompare(password, []byte(s.pipe.FromPassword)) == 1, nil
}

func (s *skelpipeFromPublicKeyWrapper) AuthorizedKeys(conn libplugin.ConnMetadata) ([]byte, error) {
	return []byte(s.pipe.FromAuthorizedKeys.Data), nil
}

func (s *skelpipeFromPublicKeyWrapper) TrustedUserCAKeys(conn libplugin.ConnMetadata) ([]byte, error) {
	return nil, nil // TODO support this
}

func (s *skelpipeToPrivateKeyWrapper) PrivateKey(conn libplugin.ConnMetadata) ([]byte, []byte, error) {
	return []byte(s.pipe.ToPrivateKey.Data), nil, nil
}

func (s *skelpipeToPasswordWrapper) OverridePassword(conn libplugin.ConnMetadata) ([]byte, error) {
	if s.pipe.ToPassword == "" {
		return nil, nil
	}
	return []byte(s.pipe.ToPassword), nil
}

func (p *plugin) listPipe(conn libplugin.ConnMetadata) ([]skel.SkelPipe, error) {

	pipe, err := p.loadPipeFromDB(conn)
	if err != nil {
		return nil, err
	}

	return []skel.SkelPipe{&skelpipeWrapper{
		pipe: &pipe,
	}}, nil
}
