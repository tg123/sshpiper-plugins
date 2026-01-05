package main

import (
	"fmt"
	"os"
	"path"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/tg123/sshpiper-plugins/internal/testcommon"
)

func createTestPlugin(backend createdb) *plugin {
	p := &plugin{
		logmode: true,
	}

	err := p.Init(backend)

	if err != nil {
		panic(fmt.Sprintf("failed to init plugin: %v", err))
	}

	return p
}

func TestSqliteDatabase(t *testing.T) {

	if testing.Short() {
		t.Skip("skipping database e2e tests in short mode")
	}

	testdir, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	dbfile := path.Join(testdir, "test.db")

	plugin := createTestPlugin(&sqliteplugin{
		File: dbfile,
	})
	defer plugin.Close()

	sqlite3db := plugin.db

	// upstream key
	if err := testcommon.RunCmdAndWait("rm", "-f", path.Join(testdir, "id_rsa")); err != nil {
		t.Errorf("failed to remove id_rsa: %v", err)
	}

	if err := testcommon.RunCmdAndWait(
		"ssh-keygen",
		"-N",
		"",
		"-f",
		path.Join(testdir, "id_rsa"),
	); err != nil {
		t.Errorf("failed to generate private key: %v", err)
	}

	if err := testcommon.RunCmdAndWait(
		"/bin/cp",
		path.Join(testdir, "id_rsa.pub"),
		"/sshconfig_publickey/.ssh/authorized_keys",
	); err != nil {
		t.Errorf("failed to copy public key: %v", err)
	}

	upstreamPrivateKeyData, err := os.ReadFile(path.Join(testdir, "id_rsa"))
	if err != nil {
		t.Errorf("failed to read private key: %v", err)
	}

	knownHostsKeyData, err := testcommon.RunAndGetStdout(
		"ssh-keyscan",
		"-p",
		"2222",
		"host-publickey",
	)

	if err != nil {
		t.Errorf("failed to run ssh-keyscan: %v", err)
	}

	knownHostsPassData, err := testcommon.RunAndGetStdout(
		"ssh-keyscan",
		"-p",
		"2222",
		"host-password",
	)

	if err != nil {
		t.Errorf("failed to run ssh-keyscan : %v", err)
	}

	t.Run("passtopass", func(t *testing.T) {

		sqlite3db.Create(&downstream{
			Username:    "passpass",
			AuthMapType: authMapTypePassword,
			Upstream: upstream{
				Username:    "user",
				AuthMapType: authMapTypePassword,
				Server: server{
					Address:       "host-password:2222",
					IgnoreHostKey: true,
				},
			},
		})

		piperaddr, piperport := testcommon.NextAvailablePiperAddress()

		piper, _, _, err := testcommon.RunCmd("/sshpiperd/sshpiperd",
			"-p",
			piperport,
			"/sshpiperd/plugins/database",
			"--driver",
			"sqlite3",
			"--sqlite-file",
			dbfile,
		)

		if err != nil {
			t.Errorf("failed to run sshpiperd: %v", err)
		}

		defer testcommon.KillCmd(piper)

		testcommon.WaitForEndpointReady(piperaddr)

		randtext := uuid.New().String()
		targetfie := uuid.New().String()

		c, stdin, stdout, err := testcommon.RunCmd(
			"ssh",
			"-v",
			"-o",
			"StrictHostKeyChecking=no",
			"-p",
			piperport,
			"-l",
			"passpass",
			"127.0.0.1",
			fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfie),
		)

		if err != nil {
			t.Errorf("failed to ssh to %v", err)
		}

		defer testcommon.KillCmd(c)

		testcommon.EnterPassword(stdin, stdout, "pass")

		time.Sleep(time.Second)

		testcommon.CheckSharedFileContent(t, targetfie, randtext)
	})

	t.Run("passoverride", func(t *testing.T) {

		sqlite3db.Create(&downstream{
			Username:    "passoverride",
			AuthMapType: authMapTypePassword,
			Password:    "newpass",
			Upstream: upstream{
				Username:    "user",
				Password:    "pass",
				AuthMapType: authMapTypePassword,
				Server: server{
					Address: "host-password:2222",
					HostKey: keydata{
						Data: string(knownHostsPassData),
					},
				},
			},
		})

		piperaddr, piperport := testcommon.NextAvailablePiperAddress()

		piper, _, _, err := testcommon.RunCmd("/sshpiperd/sshpiperd",
			"-p",
			piperport,
			"/sshpiperd/plugins/database",
			"--driver",
			"sqlite3",
			"--sqlite-file",
			dbfile,
		)

		if err != nil {
			t.Errorf("failed to run sshpiperd: %v", err)
		}

		defer testcommon.KillCmd(piper)

		testcommon.WaitForEndpointReady(piperaddr)

		randtext := uuid.New().String()
		targetfie := uuid.New().String()

		c, stdin, stdout, err := testcommon.RunCmd(
			"ssh",
			"-v",
			"-o",
			"StrictHostKeyChecking=no",
			"-p",
			piperport,
			"-l",
			"passoverride",
			"127.0.0.1",
			fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfie),
		)

		if err != nil {
			t.Errorf("failed to ssh to %v", err)
		}

		defer testcommon.KillCmd(c)

		testcommon.EnterPassword(stdin, stdout, "newpass")

		time.Sleep(time.Second)

		testcommon.CheckSharedFileContent(t, targetfie, randtext)
	})

	t.Run("keytokey", func(t *testing.T) {

		if err := testcommon.RunCmdAndWait("rm", "-f", path.Join(testdir, "keykey")); err != nil {
			t.Errorf("failed to remove id_rsa: %v", err)
		}

		if err := testcommon.RunCmdAndWait(
			"ssh-keygen",
			"-N",
			"",
			"-f",
			path.Join(testdir, "keykey"),
		); err != nil {
			t.Errorf("failed to generate private key: %v", err)
		}

		pk, err := os.ReadFile(path.Join(testdir, "keykey.pub"))
		if err != nil {
			t.Errorf("failed to read public key: %v", err)
		}

		if err := sqlite3db.Create(&downstream{
			Username:    "keykey",
			AuthMapType: authMapTypePrivateKey,
			AuthorizedKeys: keydata{
				Data: string(pk),
			},
			Upstream: upstream{
				Username:    "user",
				AuthMapType: authMapTypePrivateKey,
				PrivateKey: keydata{
					Data: string(upstreamPrivateKeyData),
				},
				Server: server{
					Address: "host-publickey:2222",
					HostKey: keydata{
						Data: string(knownHostsKeyData),
					},
				},
			},
		}).Error; err != nil {
			t.Errorf("failed to create downstream: %v", err)
		}

		piperaddr, piperport := testcommon.NextAvailablePiperAddress()

		piper, _, _, err := testcommon.RunCmd("/sshpiperd/sshpiperd",
			"-p",
			piperport,
			"/sshpiperd/plugins/database",
			"--driver",
			"sqlite3",
			"--sqlite-file",
			dbfile,
		)

		if err != nil {
			t.Errorf("failed to run sshpiperd: %v", err)
		}

		defer testcommon.KillCmd(piper)

		testcommon.WaitForEndpointReady(piperaddr)

		randtext := uuid.New().String()
		targetfie := uuid.New().String()

		c, _, _, err := testcommon.RunCmd(
			"ssh",
			"-v",
			"-o",
			"StrictHostKeyChecking=no",
			"-p",
			piperport,
			"-l",
			"keykey",
			"-i",
			path.Join(testdir, "keykey"),
			"127.0.0.1",
			fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfie),
		)

		if err != nil {
			t.Errorf("failed to ssh to %v", err)
		}

		defer testcommon.KillCmd(c)

		time.Sleep(time.Second)

		testcommon.CheckSharedFileContent(t, targetfie, randtext)
	})

	t.Run("keytopass", func(t *testing.T) {

		if err := testcommon.RunCmdAndWait("rm", "-f", path.Join(testdir, "keypass")); err != nil {
			t.Errorf("failed to remove id_rsa: %v", err)
		}

		if err := testcommon.RunCmdAndWait(
			"ssh-keygen",
			"-N",
			"",
			"-f",
			path.Join(testdir, "keypass"),
		); err != nil {
			t.Errorf("failed to generate private key: %v", err)
		}

		pk, err := os.ReadFile(path.Join(testdir, "keypass.pub"))
		if err != nil {
			t.Errorf("failed to read public key: %v", err)
		}

		sqlite3db.Create(&downstream{
			Username:    "keypass",
			AuthMapType: authMapTypePrivateKey,
			AuthorizedKeys: keydata{
				Data: string(pk),
			},
			Upstream: upstream{
				Username:    "user",
				AuthMapType: authMapTypePassword,
				Password:    "pass",
				Server: server{
					Address: "host-password:2222",
					HostKey: keydata{
						Data: string(knownHostsPassData),
					},
				},
			},
		})

		piperaddr, piperport := testcommon.NextAvailablePiperAddress()

		piper, _, _, err := testcommon.RunCmd("/sshpiperd/sshpiperd",
			"-p",
			piperport,
			"/sshpiperd/plugins/database",
			"--driver",
			"sqlite3",
			"--sqlite-file",
			dbfile,
		)

		if err != nil {
			t.Errorf("failed to run sshpiperd: %v", err)
		}

		defer testcommon.KillCmd(piper)

		testcommon.WaitForEndpointReady(piperaddr)

		randtext := uuid.New().String()
		targetfie := uuid.New().String()

		c, _, _, err := testcommon.RunCmd(
			"ssh",
			"-v",
			"-o",
			"StrictHostKeyChecking=no",
			"-p",
			piperport,
			"-l",
			"keypass",
			"-i",
			path.Join(testdir, "keypass"),
			"127.0.0.1",
			fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfie),
		)

		if err != nil {
			t.Errorf("failed to ssh to %v", err)
		}

		defer testcommon.KillCmd(c)

		time.Sleep(time.Second)

		testcommon.CheckSharedFileContent(t, targetfie, randtext)
	})
}
