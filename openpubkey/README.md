# openpubkey plugin for sshpiperd

Authenticate upstream connections with [openpubkey](https://github.com/openpubkey/openpubkey). The plugin generates an SSH key on the fly, obtains an OpenPubKey-signed certificate after the user approves via browser, and uses it to connect to the upstream server without storing long-lived private keys.

Environment variables / flags:

- `--webaddr` (`SSHPIPERD_OPENPUBKEY_WEBADDR`, default `:3000`)
- `--baseurl` (`SSHPIPERD_OPENPUBKEY_BASEURL`, required) public URL for the web callback
- `--clientid` (`SSHPIPERD_OPENPUBKEY_CLIENTID`, required) OIDC client ID
- `--clientsecret` (`SSHPIPERD_OPENPUBKEY_CLIENTSECRET`, required) OIDC client secret
- `--issuerurl` (`SSHPIPERD_OPENPUBKEY_ISSUERURL`, required) OIDC issuer URL

Running the plugin:

```bash
SSHPIPERD_OPENPUBKEY_BASEURL=https://opk.sshpiper.com \
SSHPIPERD_OPENPUBKEY_CLIENTID=<client id> \
SSHPIPERD_OPENPUBKEY_CLIENTSECRET=<client secret> \
SSHPIPERD_OPENPUBKEY_ISSUERURL=https://accounts.google.com \
sshpiperd openpubkey --baseurl $SSHPIPERD_OPENPUBKEY_BASEURL --clientid $SSHPIPERD_OPENPUBKEY_CLIENTID --clientsecret $SSHPIPERD_OPENPUBKEY_CLIENTSECRET --issuerurl $SSHPIPERD_OPENPUBKEY_ISSUERURL
```

See the original project at https://github.com/tg123/sshpiper-openpubkey for a Docker compose example to set up an SSH server that trusts OpenPubKey certificates.
