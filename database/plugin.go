package main

import (
	log "github.com/sirupsen/logrus"

	"github.com/jinzhu/gorm"
)

type createdb interface {
	create() (*gorm.DB, error)
}

type plugin struct {
	db      *gorm.DB
	logmode bool
}

func (p *plugin) Init(backend createdb) error {

	db, err := backend.create()

	if err != nil {
		return err
	}

	log.Printf("upstream provider: Database driver [%v] initializing", db.Dialect().GetName())

	err = db.AutoMigrate(
		new(keydata),
		new(server),
		new(upstream),
		new(downstream),
		new(config),
	).Error

	if err != nil {
		log.Printf("AutoMigrate error: %v", err)
		return err
	}

	db.SetLogger(log.StandardLogger())
	db.LogMode(p.logmode)

	p.db = db

	return nil
}

// Close
func (p *plugin) Close() {
	if p.db != nil {
		p.db.Close()
	}
}
