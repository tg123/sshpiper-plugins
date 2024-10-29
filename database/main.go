package main

import (
	"fmt"

	"github.com/tg123/sshpiper/libplugin"
	"github.com/urfave/cli/v2"
)

func main() {

	libplugin.CreateAndRunPluginTemplate(&libplugin.PluginTemplate{
		Name:  "database plugin for sshpiperd",
		Usage: "sshpiperd database plugin, support sqlite3, mysql, postgres, mssql",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "driver",
				Usage:    "database driver, one of sqlite3, mysql, postgres, mssql",
				EnvVars:  []string{"SSHPIPERD_DATABASE_DRIVER"},
				Required: true,
			},

			// sqlite3
			&cli.StringFlag{
				Name:     "sqlite-file",
				Required: false,
				EnvVars:  []string{"SSHPIPERD_DATABASE_SQLITE_FILE"},
			},

			// mysql
			&cli.StringFlag{
				Name:    "mysql-host",
				Value:   "127.0.0.1",
				Usage:   "MySQL host",
				EnvVars: []string{"SSHPIPERD_DATABASE_MYSQL_HOST"},
			},
			&cli.StringFlag{
				Name:    "mysql-user",
				Value:   "root",
				Usage:   "MySQL user",
				EnvVars: []string{"SSHPIPERD_DATABASE_MYSQL_USER"},
			},
			&cli.StringFlag{
				Name:    "mysql-password",
				Value:   "",
				Usage:   "MySQL password",
				EnvVars: []string{"SSHPIPERD_DATABASE_MYSQL_PASSWORD"},
			},
			&cli.UintFlag{
				Name:    "mysql-port",
				Value:   3306,
				Usage:   "MySQL port",
				EnvVars: []string{"SSHPIPERD_DATABASE_MYSQL_PORT"},
			},
			&cli.StringFlag{
				Name:    "mysql-dbname",
				Value:   "sshpiper",
				Usage:   "MySQL database name",
				EnvVars: []string{"SSHPIPERD_DATABASE_MYSQL_DBNAME"},
			},

			// postgres
			&cli.StringFlag{
				Name:    "postgres-host",
				Value:   "127.0.0.1",
				Usage:   "PostgreSQL host",
				EnvVars: []string{"SSHPIPERD_DATABASE_POSTGRES_HOST"},
			},
			&cli.StringFlag{
				Name:    "postgres-user",
				Value:   "postgres",
				Usage:   "PostgreSQL user",
				EnvVars: []string{"SSHPIPERD_DATABASE_POSTGRES_USER"},
			},
			&cli.StringFlag{
				Name:    "postgres-password",
				Value:   "",
				Usage:   "PostgreSQL password",
				EnvVars: []string{"SSHPIPERD_DATABASE_POSTGRES_PASSWORD"},
			},
			&cli.UintFlag{
				Name:    "postgres-port",
				Value:   5432,
				Usage:   "PostgreSQL port",
				EnvVars: []string{"SSHPIPERD_DATABASE_POSTGRES_PORT"},
			},
			&cli.StringFlag{
				Name:    "postgres-dbname",
				Value:   "sshpiper",
				Usage:   "PostgreSQL database name",
				EnvVars: []string{"SSHPIPERD_DATABASE_POSTGRES_DBNAME"},
			},
			&cli.StringFlag{
				Name:    "postgres-sslmode",
				Value:   "require",
				Usage:   "PostgreSQL SSL mode",
				EnvVars: []string{"SSHPIPERD_DATABASE_POSTGRES_SSLMODE"},
			},
			&cli.StringFlag{
				Name:    "postgres-sslcert",
				Value:   "",
				Usage:   "PostgreSQL SSL cert path",
				EnvVars: []string{"SSHPIPERD_DATABASE_POSTGRES_SSLCERT"},
			},
			&cli.StringFlag{
				Name:    "postgres-sslkey",
				Value:   "",
				Usage:   "PostgreSQL SSL key path",
				EnvVars: []string{"SSHPIPERD_DATABASE_POSTGRES_SSLKEY"},
			},
			&cli.StringFlag{
				Name:    "postgres-sslrootcert",
				Value:   "",
				Usage:   "PostgreSQL SSL root cert path",
				EnvVars: []string{"SSHPIPERD_DATABASE_POSTGRES_SSLROOTCERT"},
			},

			// mssql
			&cli.StringFlag{
				Name:    "mssql-host",
				Value:   "127.0.0.1",
				Usage:   "SQL Server host",
				EnvVars: []string{"SSHPIPERD_DATABASE_MSSQL_HOST"},
			},
			&cli.StringFlag{
				Name:    "mssql-user",
				Value:   "sa",
				Usage:   "SQL Server user",
				EnvVars: []string{"SSHPIPERD_DATABASE_MSSQL_USER"},
			},
			&cli.StringFlag{
				Name:    "mssql-password",
				Value:   "",
				Usage:   "SQL Server password",
				EnvVars: []string{"SSHPIPERD_DATABASE_MSSQL_PASSWORD"},
			},
			&cli.UintFlag{
				Name:    "mssql-port",
				Value:   1433,
				Usage:   "SQL Server port",
				EnvVars: []string{"SSHPIPERD_DATABASE_MSSQL_PORT"},
			},
			&cli.StringFlag{
				Name:    "mssql-dbname",
				Value:   "sshpiper",
				Usage:   "SQL Server database name",
				EnvVars: []string{"SSHPIPERD_DATABASE_MSSQL_DBNAME"},
			},
			&cli.StringFlag{
				Name:    "mssql-instance",
				Value:   "",
				Usage:   "SQL Server database instance",
				EnvVars: []string{"SSHPIPERD_DATABASE_MSSQL_INSTANCE"},
			},
		},
		CreateConfig: func(c *cli.Context) (*libplugin.SshPiperPluginConfig, error) {

			var backend createdb

			switch c.String("driver") {
			case "sqlite3":
				backend = &sqliteplugin{
					File: c.String("sqlite-file"),
				}
				
			case "mysql":
				backend = &mysqlplugin{
					Host:     c.String("mysql-host"),
					User:     c.String("mysql-user"),
					Password: c.String("mysql-password"),
					Port:     c.Uint("mysql-port"),
					Dbname:   c.String("mysql-dbname"),
				}
			case "postgres":
				backend = &postgresplugin{
					Host:        c.String("postgres-host"),
					User:        c.String("postgres-user"),
					Password:    c.String("postgres-password"),
					Port:        c.Uint("postgres-port"),
					Dbname:      c.String("postgres-dbname"),
					SslMode:     c.String("postgres-sslmode"),
					SslCert:     c.String("postgres-sslcert"),
					SslKey:      c.String("postgres-sslkey"),
					SslRootCert: c.String("postgres-sslrootcert"),
				}
			case "mssql":
				backend = &mssqlplugin{
					Host:     c.String("mssql-host"),
					User:     c.String("mssql-user"),
					Password: c.String("mssql-password"),
					Port:     c.Uint("mssql-port"),
					Dbname:   c.String("mssql-dbname"),
					Instance: c.String("mssql-instance"),
				}
			default:
				return nil, fmt.Errorf("unknown driver %s", c.String("driver"))
			}

			p := &plugin{}

			if err := p.Init(backend); err != nil {
				return nil, err
			}

			skel := libplugin.NewSkelPlugin(p.listPipe)
			return skel.CreateConfig(), nil
		},
	})
}
