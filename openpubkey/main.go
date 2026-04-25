package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/openpubkey/openpubkey/util"
	"github.com/sethvargo/go-limiter/memorystore"
	log "github.com/sirupsen/logrus"
	webutil "github.com/tg123/sshpiper-plugins/internal/web"
	"github.com/tg123/sshpiper/libplugin"
	"github.com/urfave/cli/v2"
	"github.com/zitadel/oidc/v2/pkg/client/rp"
	"github.com/zitadel/oidc/v2/pkg/oidc"
)

const errMsgPipeApprove = "ok"
const errMsgBadUpstream = "bad upstream"

type upstreamInfo struct {
	Host string
	Port int
	User string
}

func main() {
	gin.DefaultWriter = os.Stderr

	libplugin.CreateAndRunPluginTemplate(&libplugin.PluginTemplate{
		Name:  "openpubkey",
		Usage: "sshpiperd openpubkey plugin",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "webaddr",
				Value:   ":3000",
				EnvVars: []string{"SSHPIPERD_OPENPUBKEY_WEBADDR"},
			},
			&cli.StringFlag{
				Name:     "baseurl",
				EnvVars:  []string{"SSHPIPERD_OPENPUBKEY_BASEURL"},
				Required: true,
			},
			&cli.StringFlag{
				Name:     "clientid",
				EnvVars:  []string{"SSHPIPERD_OPENPUBKEY_CLIENTID"},
				Required: true,
			},
			&cli.StringFlag{
				Name:     "clientsecret",
				EnvVars:  []string{"SSHPIPERD_OPENPUBKEY_CLIENTSECRET"},
				Required: true,
			},
			&cli.StringFlag{
				Name:     "issuerurl",
				EnvVars:  []string{"SSHPIPERD_OPENPUBKEY_ISSUERURL"},
				Required: true,
			},
		},
		CreateConfig: func(c *cli.Context) (*libplugin.SshPiperPluginConfig, error) {

			store := webutil.NewSessionStore()

			baseurl := c.String("baseurl")
			issuerurl := c.String("issuerurl")

			w, err := newWeb(oidcconfig{
				clientId:     c.String("clientid"),
				clientSecret: c.String("clientsecret"),
				baseurl:      baseurl,
				issuer:       issuerurl,
			}, store)

			if err != nil {
				return nil, err
			}

			webutil.RunWebServer(w, c.String("webaddr"), false)

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
					lasterr := store.GetSshError(session)

					// retry
					if lasterr != nil {
						lastErrMsg := *lasterr
						if lastErrMsg != errMsgBadUpstream {

							// retry with no err set, using default err
							if lastErrMsg == "" {
								lastErrMsg = errMsgBadUpstream
							}

							notifyClient(client, fmt.Sprintf("connection failed %v", lastErrMsg))
							store.SetSshError(session, errMsgBadUpstream) // set already notified
						}

						return nil, fmt.Errorf("retry not allowed")
					}

					// new session
					store.SetSshError(session, "") // set waiting for approval

					defer func() {
						if err != nil {
							store.SetSshError(session, err.Error())
						}
					}()

					signer, err := util.GenKeyPair(algo)
					if err != nil {
						return nil, err
					}

					cic, err := generateCic(signer)
					if err != nil {
						return nil, err
					}

					nonce, err := cic.Hash()
					if err != nil {
						return nil, err
					}

					setNonce(store, session, nonce)

					webutil.PromptPipe(client, baseurl, session)

					st := time.Now()

					for {

						if time.Now().After(st.Add(time.Second * 60)) {
							return nil, fmt.Errorf("timeout waiting for approval")
						}

						lasterr := store.GetSshError(session)
						if lasterr != nil && *lasterr != "" {
							return nil, fmt.Errorf("%s", *lasterr)
						}

						upstream := getUpstream(store, session)
						if upstream == "" {
							time.Sleep(time.Millisecond * 100)
							continue
						}

						token := store.GetSecret(session)
						if token == nil {
							return nil, fmt.Errorf("secret expired")
						}

						seckeySshBytes, certBytes, err := generateSshCert(token, signer, cic, issuerurl)
						if err != nil {
							return nil, err
						}

						target, err := parseUpstream(upstream)
						if err != nil {
							return nil, err
						}

						notifyClient(client, fmt.Sprintf("session approved, connecting to %v", upstream))

						return &libplugin.Upstream{
							Host:          target.Host,
							Port:          int32(target.Port),
							UserName:      target.User,
							Auth:          libplugin.CreatePrivateKeyAuth(seckeySshBytes, certBytes),
							IgnoreHostKey: true,
						}, nil
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
			}, nil
		},
	})
}

func parseUpstream(data string) (info upstreamInfo, err error) {
	host := strings.TrimSpace(data)

	t := strings.SplitN(host, "@", 2)

	if len(t) > 1 {
		info.User = t[0]
		host = t[1]
	}

	info.Host, info.Port, err = libplugin.SplitHostPortForSSH(host)
	return
}

func notifyClient(client libplugin.KeyboardInteractiveChallenge, message string) {
	if _, err := client("", message, "", false); err != nil {
		log.WithError(err).Debug("failed to send interactive prompt")
	}
}

func setNonce(store *webutil.SessionStore, session string, nonce []byte) {
	store.SetBytes(session, "nonce", nonce)
}

func getNonce(store *webutil.SessionStore, session string) []byte {
	return store.GetBytes(session, "nonce")
}

func setUpstream(store *webutil.SessionStore, session, upstream string) {
	store.SetString(session, webutil.KeyUpstream, upstream)
}

func getUpstream(store *webutil.SessionStore, session string) string {
	if v, ok := store.GetString(session, webutil.KeyUpstream); ok {
		return v
	}
	return ""
}

func deleteSession(store *webutil.SessionStore, session string, keeperr bool) {
	store.Reset(session, keeperr, "nonce")
}

type contextKey string

const nonceKey contextKey = "nonce"

type opkWeb struct {
	*webutil.WebApp
	store *webutil.SessionStore

	provider rp.RelyingParty
}

type oidcconfig struct {
	clientId     string
	clientSecret string
	baseurl      string
	issuer       string
}

func newWeb(config oidcconfig, store *webutil.SessionStore) (*opkWeb, error) {
	app := webutil.NewWebApp()
	app.LoadTemplate()

	provider, err := rp.NewRelyingPartyOIDC(
		config.issuer,
		config.clientId,
		config.clientSecret,
		fmt.Sprintf("%s/login-callback", config.baseurl),
		[]string{"openid", "profile", "email"},
		rp.WithVerifierOpts(
			rp.WithNonce(func(ctx context.Context) string { return ctx.Value(nonceKey).(string) }),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("error creating provider: %w", err)
	}

	w := &opkWeb{
		WebApp:   app,
		store:    store,
		provider: provider,
	}

	app.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, webutil.TemplateFile, gin.H{
			"session": "",
		})
	})
	app.GET("/pipe/:session", w.pipe)
	app.GET("/lasterr/:session", w.lasterr)
	app.GET("/login-callback", w.loginCallback)
	app.POST("/approve", w.approve)

	return w, nil
}

func (w *opkWeb) approve(c *gin.Context) {
	session := c.PostForm("session")
	if session == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"status": "error",
			"error":  "missing session",
		})
		return
	}

	if secret := w.store.GetSecret(session); secret == nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"status": "error",
			"error":  "invalid or expired session",
		})
		return
	}

	upstream := c.PostForm("upstream")
	if upstream == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"status": "error",
			"error":  "missing upstream",
		})
		return
	}

	if _, err := parseUpstream(upstream); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"status": "error",
			"error":  "invalid upstream",
		})
		return
	}

	setUpstream(w.store, session, upstream)

	c.JSON(http.StatusOK, gin.H{
		"status": "ok",
	})
}

func (w *opkWeb) lasterr(c *gin.Context) {
	session := c.Param("session")

	errmsg := w.store.GetSshError(session)
	if errmsg == nil {
		c.JSON(http.StatusOK, gin.H{
			"status": "unknown",
		})
		return
	}

	if *errmsg == "" {
		c.JSON(http.StatusOK, gin.H{
			"status": "unknown",
		})
		return
	}

	if *errmsg == errMsgPipeApprove {
		c.JSON(http.StatusOK, gin.H{
			"status": "approved",
		})
	} else {
		c.JSON(http.StatusOK, gin.H{
			"status": "error",
			"error":  *errmsg,
		})
	}
}

func (w *opkWeb) pipe(c *gin.Context) {
	session := c.Param("session")

	if session == "" {
		c.AbortWithError(http.StatusBadRequest, fmt.Errorf("missing session"))
		return
	}

	nonce := getNonce(w.store, session)
	if nonce == nil {
		c.AbortWithError(http.StatusBadRequest, fmt.Errorf("session expired"))
		return
	}

	url := rp.AuthURL(session, w.provider, rp.AuthURLOpt(rp.WithURLParam("nonce", string(nonce))))

	c.Redirect(http.StatusTemporaryRedirect, url)
}

func (w *opkWeb) loginCallback(c *gin.Context) {
	session := c.Query("state")
	if session == "" {
		c.AbortWithError(http.StatusBadRequest, fmt.Errorf("missing session"))
		return
	}

	nonce := getNonce(w.store, session)
	if nonce == nil {
		c.AbortWithError(http.StatusBadRequest, fmt.Errorf("session expired"))
		return
	}

	codeExchangeHandler := func(_ http.ResponseWriter, _ *http.Request, tokens *oidc.Tokens[*oidc.IDTokenClaims], _ string, _ rp.RelyingParty) {
		w.store.SetSecret(session, []byte(tokens.IDToken))
		c.HTML(http.StatusOK, webutil.TemplateFile, gin.H{
			"session": session,
		})
	}

	rp.CodeExchangeHandler(codeExchangeHandler, w.provider)(c.Writer, c.Request.WithContext(context.WithValue(c.Request.Context(), nonceKey, string(nonce))))
}
