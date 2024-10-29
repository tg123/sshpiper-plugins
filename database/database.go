package main

import (
	"github.com/jinzhu/gorm"
	"github.com/tg123/sshpiper/libplugin"
)

type pipeConfig struct {
	Username              string
	UpstreamHost          string
	MappedUsername        string
	FromType              authMapType
	FromPassword          string
	FromPrivateKey        keydata
	FromAuthorizedKeys    keydata
	FromAllowAnyPublicKey bool
	ToType                authMapType
	ToPassword            string
	ToPrivateKey          keydata
	ToAuthorizedKeys      keydata
	NoPassthrough         bool
	KnownHosts            keydata
	IgnoreHostkey         bool
}

func (p *plugin) loadPipeFromDB(conn libplugin.ConnMetadata) (pipeConfig, error) {

	user := conn.User()
	d, err := lookupDownstreamWithFallback(p.db, user)

	if err != nil {
		return pipeConfig{}, err
	}

	pipe := pipeConfig{
		Username:              user,
		UpstreamHost:          d.Upstream.Server.Address,
		MappedUsername:        d.Upstream.Username,
		FromType:              d.AuthMapType,
		FromPassword:          d.Password,
		FromAuthorizedKeys:    d.AuthorizedKeys,
		FromAllowAnyPublicKey: d.AllowAnyPublicKey,
		ToType:                d.Upstream.AuthMapType,
		ToPassword:            d.Upstream.Password,
		ToPrivateKey:          d.Upstream.PrivateKey,
		NoPassthrough:         d.NoPassthrough,
		KnownHosts:            d.Upstream.KnownHosts,
		IgnoreHostkey:         d.Upstream.Server.IgnoreHostKey,
	}

	return pipe, nil
}

func lookupDownstreamWithFallback(db *gorm.DB, user string) (*downstream, error) {
	d, err := lookupDownstream(db, user)

	if gorm.IsRecordNotFoundError(err) {
		fallback, _ := lookupConfigValue(db, fallbackUserEntry)

		if len(fallback) > 0 {
			return lookupDownstream(db, fallback)
		}
	}

	return d, err
}

func lookupDownstream(db *gorm.DB, user string) (*downstream, error) {
	d := downstream{}

	if err := db.Set("gorm:auto_preload", true).Where(&downstream{Username: user}).First(&d).Error; err != nil {

		return nil, err
	}

	return &d, nil
}

func lookupConfigValue(db *gorm.DB, entry string) (string, error) {
	c := config{}
	if err := db.Where(&config{Entry: entry}).First(&c).Error; err != nil {
		return "", err
	}

	return c.Value, nil
}
