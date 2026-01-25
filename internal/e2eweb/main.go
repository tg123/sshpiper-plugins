//go:build e2e
// +build e2e

package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tg123/sshpiper-plugins/internal/web"
	"github.com/tg123/sshpiper/libplugin"
	"github.com/urfave/cli/v2"
)

const (
	errMsgPipeApprove    = "ok"
	approvalTimeout      = time.Minute
	approvalPollInterval = 100 * time.Millisecond
)

type sessionstore interface {
	GetSecret(session string) ([]byte, error)
	SetSecret(session string, secret []byte) error

	GetUpstream(session string) (upstream string, err error)
	SetUpstream(session string, upstream string) error

	SetSshError(session string, err string) error
	GetSshError(session string) (err *string)

	DeleteSession(session string, keeperr bool) error
}

type sessionstoreMemory struct{ store *web.SessionStore }

func newSessionstoreMemory() (*sessionstoreMemory, error) {
	return &sessionstoreMemory{store: web.NewSessionStore()}, nil
}

func (s *sessionstoreMemory) GetSecret(session string) ([]byte, error) {
	return s.store.GetBytes(session, "secret"), nil
}

func (s *sessionstoreMemory) SetSecret(session string, secret []byte) error {
	s.store.SetBytes(session, "secret", secret)
	return nil
}

func (s *sessionstoreMemory) GetUpstream(session string) (string, error) {
	u, ok := s.store.GetString(session, "upstream")
	if !ok {
		return "", nil
	}
	return u, nil
}

func (s *sessionstoreMemory) SetUpstream(session string, upstream string) error {
	s.store.SetString(session, "upstream", upstream)
	return nil
}

func (s *sessionstoreMemory) SetSshError(session string, err string) error {
	s.store.SetValue(session, "ssherror", &err)
	return nil
}

func (s *sessionstoreMemory) GetSshError(session string) (err *string) {
	v, ok := s.store.GetValue(session, "ssherror")
	if !ok {
		return nil
	}

	if e, ok := v.(*string); ok {
		return e
	}

	return nil
}

func (s *sessionstoreMemory) DeleteSession(session string, keeperr bool) error {
	s.store.Delete(session, "secret", "upstream")
	if !keeperr {
		s.store.Delete(session, "ssherror")
	}
	return nil
}

type approverWeb struct {
	store sessionstore
	r     *gin.Engine
}

const (
	headerSession  = "X-SSHPIPER-SESSION"
	headerUpstream = "X-SSHPIPER-UPSTREAM"
)

func newApproverWeb(store sessionstore) *approverWeb {
	r := gin.Default()
	w := &approverWeb{
		store: store,
		r:     r,
	}

	r.POST("/approve", w.approve)
	return w
}

func (w *approverWeb) Run(addr string) error {
	return w.r.Run(addr)
}

func (w *approverWeb) approve(c *gin.Context) {
	session := c.GetHeader(headerSession)
	upstream := c.GetHeader(headerUpstream)

	if session == "" || upstream == "" {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": "missing session or upstream"})
		return
	}

	if secret, _ := w.store.GetSecret(session); secret == nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": "invalid or expired session"})
		return
	}

	w.store.SetUpstream(session, upstream)
	w.store.SetSshError(session, errMsgPipeApprove)

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

type upstreamInfo struct {
	Host     string
	Port     int
	User     string
	Password string
}

func parseUpstream(data string) (info upstreamInfo, err error) {
	parts := strings.SplitN(data, "@", 2)
	hostpart := data
	if len(parts) == 2 {
		hostpart = parts[1]
		cred := parts[0]
		credParts := strings.SplitN(cred, ":", 2)
		info.User = credParts[0]
		if len(credParts) == 2 {
			info.Password = credParts[1]
		}
	}

	info.Host, info.Port, err = libplugin.SplitHostPortForSSH(hostpart)
	return
}

func main() {
	gin.DefaultWriter = os.Stderr

	libplugin.CreateAndRunPluginTemplate(&libplugin.PluginTemplate{
		Name:  "e2eweb",
		Usage: "sshpiperd e2e web approval plugin",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "webaddr",
				Value:   ":3000",
				EnvVars: []string{"SSHPIPERD_E2EWEB_WEBADDR"},
			},
			&cli.StringFlag{
				Name:     "baseurl",
				EnvVars:  []string{"SSHPIPERD_E2EWEB_BASEURL"},
				Required: true,
			},
		},
		CreateConfig: func(c *cli.Context) (*libplugin.SshPiperPluginConfig, error) {

			store, err := newSessionstoreMemory()
			if err != nil {
				return nil, err
			}

			baseurl := c.String("baseurl")

			w := newApproverWeb(store)
			web.RunWebServer(w, c.String("webaddr"), false)

			return &libplugin.SshPiperPluginConfig{
				KeyboardInteractiveCallback: func(conn libplugin.ConnMetadata, client libplugin.KeyboardInteractiveChallenge) (u *libplugin.Upstream, err error) {
					session := conn.UniqueID()

					lasterr := store.GetSshError(session)
					if lasterr != nil {
						return nil, errors.New("retry not allowed")
					}

					store.SetSshError(session, "")
					store.SetSecret(session, []byte("ok"))

					defer func() {
						if err != nil {
							store.SetSshError(session, err.Error())
						}
					}()

					web.PromptPipe(client, baseurl, session)

					start := time.Now()
					for {
						if time.Since(start) > approvalTimeout {
							return nil, fmt.Errorf("timeout waiting for approval")
						}

						up, _ := store.GetUpstream(session)
						if up == "" {
							time.Sleep(approvalPollInterval)
							continue
						}

						target, err := parseUpstream(up)
						if err != nil {
							return nil, err
						}

						user := target.User
						if user == "" {
							user = conn.User()
						}

						upstream := &libplugin.Upstream{
							UserName:      user,
							Host:          target.Host,
							Port:          int32(target.Port),
							IgnoreHostKey: true,
						}

						if target.Password != "" {
							upstream.Auth = libplugin.CreatePasswordAuth([]byte(target.Password))
						} else {
							upstream.Auth = libplugin.CreateNoneAuth()
						}

						store.SetSshError(session, errMsgPipeApprove)
						return upstream, nil
					}
				},
				PipeStartCallback: func(conn libplugin.ConnMetadata) {
					session := conn.UniqueID()
					store.SetSshError(session, errMsgPipeApprove)
					store.DeleteSession(session, true)
				},
				PipeErrorCallback: func(conn libplugin.ConnMetadata, err error) {
					session := conn.UniqueID()
					store.DeleteSession(session, false)
				},
			}, nil
		},
	})
}
