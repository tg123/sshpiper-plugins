package main

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/go-github/v50/github"
	"github.com/sethvargo/go-limiter/memorystore"
	webutil "github.com/tg123/sshpiper-plugins/internal/web"
	"github.com/tg123/sshpiper/libplugin"
	"github.com/tg123/sshpiper/libplugin/skel"
	"github.com/urfave/cli/v2"
	"golang.org/x/oauth2"
	githubendpoint "golang.org/x/oauth2/github"
	"gopkg.in/yaml.v3"
)

const errMsgPipeApprove = "ok"
const errMsgBadUpstreamCred = "bad upstream credential"

func main() {

	gin.DefaultWriter = os.Stderr

	libplugin.CreateAndRunPluginTemplate(&libplugin.PluginTemplate{
		Name:  "githubapp",
		Usage: "sshpiperd githubapp plugin",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "webaddr",
				Value:   ":3000",
				EnvVars: []string{"SSHPIPERD_GITHUBAPP_WEBADDR"},
			},
			&cli.StringFlag{
				Name:     "baseurl",
				EnvVars:  []string{"SSHPIPERD_GITHUBAPP_BASEURL"},
				Required: true,
			},
			&cli.StringFlag{
				Name:     "clientid",
				EnvVars:  []string{"SSHPIPERD_GITHUBAPP_CLIENTID"},
				Required: true,
			},
			&cli.StringFlag{
				Name:     "clientsecret",
				EnvVars:  []string{"SSHPIPERD_GITHUBAPP_CLIENTSECRET"},
				Required: true,
			},
		},
		CreateConfig: func(c *cli.Context) (*libplugin.SshPiperPluginConfig, error) {

			store := webutil.NewSessionStore()

			baseurl := c.String("baseurl")

			w, err := newWeb(&oauth2.Config{
				ClientID:     c.String("clientid"),
				ClientSecret: c.String("clientsecret"),
				Endpoint:     githubendpoint.Endpoint,
				RedirectURL:  fmt.Sprintf("%s/oauth2callback", baseurl),
			}, store)

			if err != nil {
				return nil, err
			}

			webutil.RunWebServer(w, c.String("webaddr"), true)

			limiter, err := memorystore.New(&memorystore.Config{
				Tokens:      3,
				Interval:    time.Minute,
				SweepMinTTL: time.Minute * 5,
			})

			if err != nil {
				return nil, err
			}

			return &libplugin.SshPiperPluginConfig{
				KeyboardInteractiveCallback: func(conn libplugin.ConnMetadata, client libplugin.KeyboardInteractiveChallenge) (u *libplugin.Upstream, err error) {
					session := conn.UniqueID()

					defer func() {
						if err != nil {
							store.SetSshError(session, err.Error())
						} else {
							store.SetSshError(session, errMsgPipeApprove) // this happens before pipestart, but it's ok because pipestart may timeout due to network issues
						}
					}()

					lasterr := store.GetSshError(session)

					if lasterr == nil {
						// new session
						webutil.PromptPipe(client, baseurl, session)
						store.SetSshError(session, "") // set waiting for approval

					} else if *lasterr != "" {

						// check if retry
						if *lasterr != errMsgBadUpstreamCred {
							_, _ = client("", fmt.Sprintf("your password/private key in sshpiper.yaml auth failed with upstream %v", *lasterr), "", false)
							store.SetSshError(session, errMsgBadUpstreamCred) // set already notified
						}

						return nil, errors.New(errMsgBadUpstreamCred)
					}

					st := time.Now()

					for {

						if time.Now().After(st.Add(time.Second * 60)) {
							return nil, fmt.Errorf("timeout waiting for approval")
						}

						upstream := getUpstream(store, session)
						if upstream == nil {
							time.Sleep(time.Millisecond * 100)
							continue
						}

						key := store.GetSecret(session)
						if key == nil {
							return nil, fmt.Errorf("secret expired")
						}

						host, port, err := libplugin.SplitHostPortForSSH(upstream.Host)
						if err != nil {
							return nil, err
						}

						var resolvedips []string
						ips, err := net.LookupIP(host)
						if err != nil {
							return nil, err
						}

						for _, ip := range ips {
							if !ip.IsPrivate() {
								resolvedips = append(resolvedips, ip.String())
							}
						}

						if len(resolvedips) == 0 {
							return nil, fmt.Errorf("no public ip found for %v", host)
						}

						// choose random ip from resolveips
						idx, err := crand.Int(crand.Reader, big.NewInt(int64(len(resolvedips))))
						if err != nil {
							return nil, err
						}
						selectedip := resolvedips[idx.Int64()]

						hosttoshow := upstream.Host

						if host != selectedip {
							hosttoshow = fmt.Sprintf("%v (%v)", upstream.Host, selectedip)
						}

						u = &libplugin.Upstream{
							UserName:      upstream.Username,
							Host:          selectedip,
							Port:          int32(port),
							IgnoreHostKey: upstream.KnownHostsData == "",
						}

						password, _ := decrypt(upstream.Password, key)
						privateKeyData, _ := decrypt(upstream.PrivateKeyData, key)

						remoteuser := upstream.Username
						if remoteuser == "" {
							remoteuser = conn.User()
						}

						if privateKeyData != "" {
							priv, err := base64.StdEncoding.DecodeString(privateKeyData)
							if err != nil {
								return nil, err
							}

							u.Auth = libplugin.CreatePrivateKeyAuth(priv)

							_, _ = client("", fmt.Sprintf("piping to %v@%v with private key", remoteuser, hosttoshow), "", false)

							return u, nil
						}

						if password != "" {
							u.Auth = libplugin.CreatePasswordAuth([]byte(password))

							_, _ = client("", fmt.Sprintf("piping to %v@%v with password", remoteuser, hosttoshow), "", false)

							return u, nil
						}

						_, _ = client("", fmt.Sprintf("piping to %v@%v with none auth", remoteuser, hosttoshow), "", false)

						u.Auth = libplugin.CreateNoneAuth()
						return u, nil
					}
				},
				NewConnectionCallback: func(conn libplugin.ConnMetadata) error {
					ip, _, _ := net.SplitHostPort(conn.RemoteAddr())
					_, _, _, ok, err := limiter.Take(context.Background(), ip)
					if err != nil {
						return err
					}

					if !ok {
						return fmt.Errorf("too many connections")
					}

					return nil
				},
				UpstreamAuthFailureCallback: func(conn libplugin.ConnMetadata, method string, err error, allowmethods []string) {
					session := conn.UniqueID()
					store.SetSshError(session, err.Error())
					deleteSession(store, session, true)
				},
				PipeStartCallback: func(conn libplugin.ConnMetadata) {
					session := conn.UniqueID()
					store.SetSshError(session, errMsgPipeApprove)
					deleteSession(store, session, true)
				},
				PipeErrorCallback: func(conn libplugin.ConnMetadata, err error) {
					session := conn.UniqueID()
					deleteSession(store, session, false)

					ip, _, _ := net.SplitHostPort(conn.RemoteAddr())
					limiter.Burst(context.Background(), ip, 1)
				},
				VerifyHostKeyCallback: func(conn libplugin.ConnMetadata, hostname, netaddr string, key []byte) error {
					session := conn.UniqueID()

					upstream := getUpstream(store, session)

					if upstream == nil {
						return fmt.Errorf("connection expired")
					}

					if upstream.KnownHostsData == "" {
						return nil
					}

					data, err := base64.StdEncoding.DecodeString(upstream.KnownHostsData)
					if err != nil {
						return err
					}

					return skel.VerifyHostKeyFromKnownHosts(bytes.NewBuffer(data), hostname, netaddr, key)
				},
			}, nil
		},
	})
}

func setUpstream(store *webutil.SessionStore, session string, upstream *upstreamConfig) {
	store.SetValue(session, webutil.KeyUpstream, upstream)
}

func getUpstream(store *webutil.SessionStore, session string) *upstreamConfig {
	v, ok := store.GetValue(session, webutil.KeyUpstream)
	if !ok {
		return nil
	}

	if u, ok := v.(*upstreamConfig); ok {
		return u
	}

	return nil
}

func deleteSession(store *webutil.SessionStore, session string, keeperr bool) {
	store.Reset(session, keeperr)
}

const appurl = "https://github.com/apps/sshpiper"

var sessionRegexp = regexp.MustCompile(`^[A-Za-z0-9-]+$`)

type appWeb struct {
	*webutil.WebApp
	store *webutil.SessionStore
	oauth *oauth2.Config
}

func newWeb(oauth *oauth2.Config, store *webutil.SessionStore) (*appWeb, error) {
	app := webutil.NewWebApp()
	app.LoadTemplate()

	w := &appWeb{
		WebApp: app,
		oauth:  oauth,
		store:  store,
	}

	app.GET("/", func(c *gin.Context) {
		c.Redirect(http.StatusTemporaryRedirect, appurl)
	})

	app.GET("/pipe/:session", w.pipe)
	app.GET("/oauth2callback", w.oauth2callback)
	app.POST("/approve/:session", w.approve)

	return w, nil
}

func (w *appWeb) pipe(c *gin.Context) {
	session := c.Param("session")

	if session == "" || !sessionRegexp.MatchString(session) {
		c.Redirect(http.StatusTemporaryRedirect, appurl)
		return
	}

	c.Redirect(http.StatusTemporaryRedirect, w.oauth.AuthCodeURL(session))
}

func (w *appWeb) approve(c *gin.Context) {
	session := c.Param("session")
	if session == "" || !sessionRegexp.MatchString(session) {
		c.Redirect(http.StatusTemporaryRedirect, appurl)
		return
	}

	upstreamConfig := &upstreamConfig{
		Host:           c.PostForm("host"),
		Username:       c.PostForm("username"),
		Password:       c.PostForm("password"),
		PrivateKeyData: c.PostForm("privatekey"),
		KnownHostsData: c.PostForm("knownhosts"),
	}

	setUpstream(w.store, session, upstreamConfig)

	var errors []string
	var infos []string
	var errmsg *string

	for {

		errmsg = w.store.GetSshError(session)
		if errmsg == nil {
			errors = append(errors, "session expired")
			break
		}

		if *errmsg == "" {
			time.Sleep(time.Millisecond * 300)
			continue
		}

		if *errmsg == errMsgPipeApprove {
			infos = append(infos, "ssh pipe approved")
		} else {
			errors = append(errors, *errmsg)
		}

		break
	}

	c.HTML(http.StatusOK, webutil.TemplateFile, gin.H{
		"errors": errors,
		"infos":  infos,
	})
}

func (w *appWeb) oauth2callback(c *gin.Context) {
	code := c.Query("code")
	session := c.Query("state")

	if code == "" || session == "" || !sessionRegexp.MatchString(session) {
		c.Redirect(http.StatusTemporaryRedirect, appurl)
		return
	}

	token, err := w.oauth.Exchange(context.Background(), code)

	if err != nil {
		c.HTML(http.StatusOK, webutil.TemplateFile, gin.H{
			"errors": []string{err.Error()},
		})
		return
	}

	tc := oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(token))
	client := github.NewClient(tc)

	repos, _, err := client.Repositories.List(context.Background(), "", &github.RepositoryListOptions{
		Visibility: "private",
	})

	if err != nil {
		c.HTML(http.StatusOK, webutil.TemplateFile, gin.H{
			"errors": []string{err.Error()},
		})
		return
	}

	key, err := randomkey()
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}

	var upstreams []upstreamConfig

	contentFound := false
	var errors []string

	for _, repo := range repos {
		if repo.FullName == nil {
			continue
		}

		fullname := strings.Split(*repo.FullName, "/")
		if len(fullname) != 2 {
			errors = append(errors, fmt.Sprintf("unexpected repo full name %q", *repo.FullName))
			continue
		}
		owner := fullname[0]
		reponame := fullname[1]
		conf, _, _, err := client.Repositories.GetContents(context.Background(), owner, reponame, "sshpiper.yaml", nil)
		if err != nil {
			errors = append(errors, fmt.Sprintf("failed to get sshpiper.yaml from %s/%s: %v", owner, reponame, err))
			continue
		}

		content, err := conf.GetContent()
		if err != nil {
			errors = append(errors, fmt.Sprintf("failed to decode sshpiper.yaml from %s/%s: %v", owner, reponame, err))
			continue
		}

		contentFound = true

		var config pipeConfig
		if err := yaml.Unmarshal([]byte(content), &config); err != nil {
			errors = append(errors, fmt.Sprintf("failed to parse sshpiper.yaml from %s/%s: %v", owner, reponame, err))
		}

		for _, upstream := range config.Upstreams {
			upstream.Password, _ = encrypt(upstream.Password, key)
			upstream.PrivateKeyData, _ = encrypt(upstream.PrivateKeyData, key)
			upstream.Repo = *repo.FullName
			upstreams = append(upstreams, upstream)
		}
	}

	if len(upstreams) > 0 {
		w.store.SetSecret(session, key)
	}

	if len(repos) == 0 {
		errors = append(errors, "no private repositories found, please install github app to any of your private repositories")
	} else if !contentFound {
		errors = append(errors, "no sshpiper.yaml found in any private repositories, please add sshpiper.yaml")
	} else if len(upstreams) == 0 {
		errors = append(errors, "no valid upstreams found in sshpiper.yaml, please check sshpiper.yaml")
	}

	c.HTML(http.StatusOK, webutil.TemplateFile, gin.H{
		"upstreams": upstreams,
		"session":   session,
		"errors":    errors,
	})
}
