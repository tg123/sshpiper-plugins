package main

import (
	"fmt"

	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/mysql" // gorm dialiect
)

type mysqlplugin struct {
	Host     string
	User     string
	Password string
	Port     uint
	Dbname   string
}

func (p *mysqlplugin) create() (*gorm.DB, error) {

	config := mysqldriver.NewConfig()
	config.User = p.User
	config.Passwd = p.Password
	config.Net = "tcp"
	config.Addr = fmt.Sprintf("%v:%v", p.Host, p.Port)
	config.DBName = p.Dbname
	config.ParseTime = true

	db, err := gorm.Open("mysql", config.FormatDSN())
	if err != nil {
		return nil, err
	}

	return db, nil
}
