package main

import webutil "github.com/tg123/sshpiper-plugins/internal/web"

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

func setSecret(store *webutil.SessionStore, session string, secret []byte) {
	store.SetBytes(session, "secret", secret)
}

func getSecret(store *webutil.SessionStore, session string) []byte {
	return store.GetBytes(session, "secret")
}

func setUpstream(store *webutil.SessionStore, session string, upstream *upstreamConfig) {
	store.SetValue(session, "upstream", upstream)
}

func getUpstream(store *webutil.SessionStore, session string) *upstreamConfig {
	v, ok := store.GetValue(session, "upstream")
	if !ok {
		return nil
	}

	if u, ok := v.(*upstreamConfig); ok {
		return u
	}

	return nil
}

func deleteSession(store *webutil.SessionStore, session string, keeperr bool) {
	store.Delete(session, "secret", "upstream")
	if !keeperr {
		store.Delete(session, "ssherror")
	}
}
