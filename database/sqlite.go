package main

import (
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite" // gorm dialect
)

type sqliteplugin struct {
	File string
}

func (p *sqliteplugin) create() (*gorm.DB, error) {

	db, err := gorm.Open("sqlite3", p.File)
	if err != nil {
		return nil, err
	}

	return db, nil
}
