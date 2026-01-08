package main

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	webutil "github.com/tg123/sshpiper-plugins/internal/web"
	"github.com/zitadel/oidc/v2/pkg/client/rp"
	"github.com/zitadel/oidc/v2/pkg/oidc"
)

func setNonce(store *webutil.SessionStore, session string, nonce []byte) {
	store.SetBytes(session, "nonce", nonce)
}

func getNonce(store *webutil.SessionStore, session string) []byte {
	return store.GetBytes(session, "nonce")
}

func setSecret(store *webutil.SessionStore, session string, secret []byte) {
	store.SetBytes(session, "secret", secret)
}

func getSecret(store *webutil.SessionStore, session string) []byte {
	return store.GetBytes(session, "secret")
}

func setUpstream(store *webutil.SessionStore, session, upstream string) {
	store.SetString(session, "upstream", upstream)
}

func getUpstream(store *webutil.SessionStore, session string) string {
	if v, ok := store.GetString(session, "upstream"); ok {
		return v
	}
	return ""
}

func setSshError(store *webutil.SessionStore, session, err string) {
	store.SetValue(session, "ssherror", &err)
}

func getSshError(store *webutil.SessionStore, session string) *string {
	v, ok := store.GetValue(session, "ssherror")
	if !ok {
		return nil
	}
	if e, ok := v.(*string); ok {
		return e
	}
	return nil
}

func deleteSession(store *webutil.SessionStore, session string, keeperr bool) {
	store.Delete(session, "secret", "upstream", "nonce")
	if !keeperr {
		store.Delete(session, "ssherror")
	}
}

const templatefile = "web.tmpl"

type contextKey string

const nonceKey contextKey = "nonce"

type opkWeb struct {
	store *webutil.SessionStore

	provider rp.RelyingParty

	r *gin.Engine
}

type oidcconfig struct {
	clientId     string
	clientSecret string
	baseurl      string
	issuer       string
}

func newWeb(config oidcconfig, store *webutil.SessionStore) (*opkWeb, error) {
	r := gin.Default()
	r.LoadHTMLFiles(templatefile)

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
		r:        r,
		store:    store,
		provider: provider,
	}

	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, templatefile, gin.H{
			"session": "",
		})
	})
	r.GET("/pipe/:session", w.pipe)
	r.GET("/lasterr/:session", w.lasterr)
	r.GET("/login-callback", w.loginCallback)
	r.POST("/approve", w.approve)

	return w, nil
}

func (w *opkWeb) Run(addr string) error {
	return w.r.Run(addr)
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

	if secret := getSecret(w.store, session); secret == nil {
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

	errmsg := getSshError(w.store, session)
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
		setSecret(w.store, session, []byte(tokens.IDToken))
		c.HTML(http.StatusOK, templatefile, gin.H{
			"session": session,
		})
	}

	rp.CodeExchangeHandler(codeExchangeHandler, w.provider)(c.Writer, c.Request.WithContext(context.WithValue(c.Request.Context(), nonceKey, string(nonce))))
}
