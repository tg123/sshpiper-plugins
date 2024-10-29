package main

import (
	"fmt"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres" // gorm dialect
)

type postgresplugin struct {
	Host        string
	User        string
	Password    string
	Port        uint
	Dbname      string
	SslMode     string
	SslCert     string
	SslKey      string
	SslRootCert string
}

func (p *postgresplugin) create() (*gorm.DB, error) {

	conn := fmt.Sprintf("host=%v port=%v user=%v password=%v dbname=%v sslmode=%v sslcert=%v sslkey=%v sslrootcert=%v",
		p.Host,
		p.Port,
		p.User,
		p.Password,
		p.Dbname,
		p.SslMode,
		p.SslCert,
		p.SslKey,
		p.SslRootCert,
	)

	db, err := gorm.Open("postgres", conn)
	if err != nil {
		return nil, err
	}

	return db, nil
}
