package openbrowser

import (
	"fmt"

	"github.com/pkg/browser"
	log "github.com/sirupsen/logrus"
	"github.com/tg123/sshpiper/libplugin"
)

const promptTemplate = "please open %v with your browser to verify (timeout 1m)"

var openURL = browser.OpenURL

func Prompt(client libplugin.KeyboardInteractiveChallenge, url string) {
	if err := openURL(url); err != nil {
		log.WithError(err).Debug("failed to open url in browser")
	}

	if _, err := client("", fmt.Sprintf(promptTemplate, url), "", false); err != nil {
		log.WithError(err).Debug("failed to send interactive prompt")
	}
}

func PromptPipe(client libplugin.KeyboardInteractiveChallenge, baseurl, session string) {
	Prompt(client, fmt.Sprintf("%v/pipe/%v", baseurl, session))
}
