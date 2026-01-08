package main

import webutil "github.com/tg123/sshpiper-plugins/internal/web"

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
