package main

import (
	"crypto/subtle"

	"github.com/tg123/sshpiper/libplugin"
)

type skelpipeWrapper struct {
	plugin *plugin

	pipe *pipeConfig
}

type skelpipeFromWrapper struct {
	skelpipeWrapper

	pipe *pipeConfig
}

type skelpipePasswordWrapper struct {
	skelpipeFromWrapper
}

type skelpipePublicKeyWrapper struct {
	skelpipeFromWrapper
}

type skelpipeToWrapper struct {
	skelpipeWrapper

	pipe *pipeConfig

	username string
}

func (s *skelpipeWrapper) From() []libplugin.SkelPipeFrom {

	w := skelpipeFromWrapper{
		skelpipeWrapper: *s,
	}

	switch s.pipe.FromType {
	case authMapTypePassword:
		return []libplugin.SkelPipeFrom{&skelpipePasswordWrapper{
			skelpipeFromWrapper: w,
		}}
	case authMapTypePrivateKey:
		return []libplugin.SkelPipeFrom{&skelpipePublicKeyWrapper{
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
	return []byte(s.pipe.KnownHosts.Data), nil
}

func (s *skelpipeFromWrapper) MatchConn(conn libplugin.ConnMetadata) (libplugin.SkelPipeTo, error) {
	return &skelpipeToWrapper{
		skelpipeWrapper: s.skelpipeWrapper,
	}, nil
}

func (s *skelpipePasswordWrapper) TestPassword(conn libplugin.ConnMetadata, password []byte) (bool, error) {
	return subtle.ConstantTimeCompare(password, []byte(s.pipe.FromPassword)) == 1, nil
}

func (s *skelpipePublicKeyWrapper) AuthorizedKeys(conn libplugin.ConnMetadata) ([]byte, error) {
	return []byte(s.pipe.FromAuthorizedKeys.Data), nil
}

func (s *skelpipePublicKeyWrapper) TrustedUserCAKeys(conn libplugin.ConnMetadata) ([]byte, error) {
	return nil, nil // TODO support this
}

func (s *skelpipeToWrapper) PrivateKey(conn libplugin.ConnMetadata) ([]byte, []byte, error) {
	return []byte(s.pipe.ToPrivateKey.Data), nil, nil
}

func (s *skelpipeToWrapper) OverridePassword(conn libplugin.ConnMetadata) ([]byte, error) {
	return []byte(s.pipe.ToPassword), nil
}

func (p *plugin) listPipe(conn libplugin.ConnMetadata) ([]libplugin.SkelPipe, error) {

	pipe, err := p.loadPipeFromDB(conn)
	if err != nil {
		return nil, err
	}

	return []libplugin.SkelPipe{&skelpipeWrapper{
		plugin: p,
		pipe:   &pipe,
	}}, nil
}
