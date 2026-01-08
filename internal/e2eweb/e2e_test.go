package main

import (
	"net/http"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/tg123/sshpiper-plugins/internal/testcommon"
)

func TestE2EWebPlugin(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping database e2e tests in short mode")
	}

	testcommon.WaitForEndpointReady("host-password:2222")
	testcommon.WaitForEndpointReady("host-publickey:2222")

	piperAddr, piperPort := testcommon.NextAvailablePiperAddress()
	webPort := strconv.Itoa(testcommon.NextAvaliablePort())

	piperArgs := []string{
		"--server-key-generate-mode", "notexist",
		"-p", piperPort,
		"/sshpiperd/plugins/e2eweb",
		"--baseurl", "http://127.0.0.1:" + webPort,
		"--webaddr", ":" + webPort,
	}

	piperCmd, _, _, err := testcommon.RunCmd("/sshpiperd/sshpiperd", piperArgs...)
	if err != nil {
		t.Fatalf("failed to start sshpiperd: %v", err)
	}
	defer testcommon.KillCmd(piperCmd)

	testcommon.WaitForEndpointReady(piperAddr)

	approveAndExpectOK(t, piperPort, webPort)
	approveAndExpectOK(t, piperPort, webPort)
}

func approveAndExpectOK(t *testing.T, piperPort, webPort string) {
	t.Helper()

	sshArgs := []string{
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-p", piperPort,
		"test@127.0.0.1",
		"echo ok",
	}

	sshCmd, _, sshOut, err := testcommon.RunCmd("ssh", sshArgs...)
	if err != nil {
		t.Fatalf("failed to start ssh: %v", err)
	}
	defer testcommon.KillCmd(sshCmd)

	reSession := regexp.MustCompile(`(?m)/pipe/([A-Za-z0-9-]+)`) // prompt embeds session id
	var session string
	testcommon.WaitForStdoutContains(sshOut, "/pipe/", func(line string) {
		if matches := reSession.FindStringSubmatch(line); len(matches) == 2 {
			session = matches[1]
		}
	})

	if session == "" {
		t.Fatal("failed to extract session id from ssh prompt")
	}

	approveSession(t, webPort, session)

	testcommon.WaitForStdoutContains(sshOut, "ok", func(_ string) {})

	waitCh := make(chan error, 1)
	go func() {
		waitCh <- sshCmd.Wait()
	}()

	select {
	case <-time.After(30 * time.Second):
		t.Fatal("ssh session did not complete in time")
	case err := <-waitCh:
		if err != nil {
			t.Fatalf("ssh command failed: %v", err)
		}
	}
}

func approveSession(t *testing.T, webPort, session string) {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, "http://127.0.0.1:"+webPort+"/approve", nil)
	if err != nil {
		t.Fatalf("failed to build approve request: %v", err)
	}
	req.Header.Set("X-SSHPIPER-SESSION", session)
	req.Header.Set("X-SSHPIPER-UPSTREAM", "user:pass@host-password:2222")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("failed to approve session: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected approve status: %v", resp.Status)
	}
}
