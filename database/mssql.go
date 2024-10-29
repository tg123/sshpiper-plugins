package main

import (
	"fmt"
	"net/url"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/mssql" // gorm dialect
)

type mssqlplugin struct {
	plugin

	Host     string
	User     string
	Password string
	Port     uint
	Dbname   string
	Instance string
}

func (p *mssqlplugin) create() (*gorm.DB, error) {
	query := url.Values{}
	query.Add("database", p.Dbname)

	u := &url.URL{
		Scheme:   "sqlserver",
		User:     url.UserPassword(p.User, p.Password),
		Host:     fmt.Sprintf("%s:%d", p.Host, p.Port),
		Path:     p.Instance,
		RawQuery: query.Encode(),
	}

	db, err := gorm.Open("mssql", u.String())
	if err != nil {
		return nil, err
	}

	return db, nil
}
