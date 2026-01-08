package main

import (
	"bufio"
	"bytes"
	"crypto/subtle"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/tg123/sshpiper/libplugin"
	"github.com/tg123/sshpiper/libplugin/skel"
	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// verifyHostKey walks every entry in the supplied known_hosts data and accepts
// the connection only if the presented key matches at least one entry for the
// target host. This avoids stopping at the first host match, which matters for
// hosts exposing multiple key types while the known_hosts contains more than
// one algorithm.
func verifyHostKey(knownHosts []byte, hostWithPort, remoteAddr string, presented []byte) error {
	pub, err := ssh.ParsePublicKey(presented)
	if err != nil {
		return err
	}

	stripBrackets := func(h string) string {
		if strings.HasPrefix(h, "[") && strings.Contains(h, "]") {
			return strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
		}
		return h
	}

	matchesHost := func(hostPattern string) bool {
		for _, h := range strings.Split(hostPattern, ",") {
			h = strings.TrimSpace(h)
			if h == "" {
				continue
			}

			targets := []string{hostWithPort, remoteAddr, stripBrackets(hostWithPort), stripBrackets(remoteAddr)}
			hStripped := stripBrackets(h)

			for _, t := range targets {
				if t == "" {
					continue
				}

				if h == t || hStripped == stripBrackets(t) {
					return true
				}
			}
		}

		return false
	}

	var wanted []knownhosts.KnownKey
	scanner := bufio.NewScanner(bytes.NewReader(knownHosts))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		hostField := fields[0]
		keyText := strings.Join(fields[1:], " ")

		knownKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(keyText))
		if err != nil {
			continue
		}

		if !matchesHost(hostField) {
			continue
		}

		if subtle.ConstantTimeCompare(knownKey.Marshal(), pub.Marshal()) == 1 {
			return nil
		}

		wanted = append(wanted, knownhosts.KnownKey{Key: knownKey})
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	if len(wanted) > 0 {
		return &knownhosts.KeyError{Want: wanted}
	}

	return &knownhosts.KeyError{}
}

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
			&cli.BoolFlag{
				Name:    "enable-database-log",
				Usage:   "enable database log",
				EnvVars: []string{"SSHPIPERD_DATABASE_ENABLE_DATABASE_LOG"},
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

			p := &plugin{
				logmode: c.Bool("enable-database-log"),
			}

			if err := p.Init(backend); err != nil {
				return nil, err
			}

			skelPlugin := skel.NewSkelPlugin(p.listPipe)
			config := skelPlugin.CreateConfig()

			origin := config.NextAuthMethodsCallback

			config.NextAuthMethodsCallback = func(conn libplugin.ConnMetadata) ([]string, error) {
				if conn.User() == "" {
					return []string{"password", "publickey"}, nil
				}

				return origin(conn)
			}

			config.VerifyHostKeyCallback = func(conn libplugin.ConnMetadata, hostname, netaddr string, key []byte) error {
				pipe, err := p.loadPipeFromDB(conn)
				if err != nil {
					return err
				}

				if pipe.IgnoreHostkey {
					return nil
				}

				wrapper := skelpipeToWrapper{
					skelpipeWrapper: skelpipeWrapper{
						pipe: &pipe,
					},
					username: pipe.MappedUsername,
				}

				data, err := wrapper.KnownHosts(conn)
				if err != nil {
					return err
				}

				if len(strings.TrimSpace(string(data))) == 0 {
					return nil
				}

				host := pipe.UpstreamHost

				hostWithPort := host
				remoteAddr := host

				if h, p, err := net.SplitHostPort(host); err == nil {
					// known_hosts entries with a port are bracketed, e.g. [host]:port
					hostWithPort = fmt.Sprintf("[%s]:%s", h, p)
					remoteAddr = hostWithPort
				}

				if err := verifyHostKey(data, hostWithPort, remoteAddr, key); err != nil {
					if parsed, perr := ssh.ParsePublicKey(key); perr == nil {
						fingerprint := ssh.FingerprintSHA256(parsed)
						if ke, ok := err.(*knownhosts.KeyError); ok && len(ke.Want) > 0 {
							var wants []string
							for _, w := range ke.Want {
								if w.Key != nil {
									wants = append(wants, ssh.FingerprintSHA256(w.Key))
								}
							}
							log.Printf("verify host key failed for %s (%s): got %s, want %s", hostWithPort, remoteAddr, fingerprint, strings.Join(wants, ", "))
							log.Printf("known hosts data for %s:\n%s", hostWithPort, string(data))
						} else {
							log.Printf("verify host key failed for %s (%s): %s (%v)", hostWithPort, remoteAddr, fingerprint, err)
						}
					} else {
						log.Printf("verify host key failed for %s (%s): %v", hostWithPort, remoteAddr, err)
					}

					return err
				}

				return nil
			}

			return config, nil
		},
	})
}
