package web

import "testing"

type sample struct {
	Name string
}

func TestSessionStore(t *testing.T) {
	store := NewSessionStore()

	store.SetBytes("s1", "secret", []byte{1, 2, 3})
	if got := store.GetBytes("s1", "secret"); len(got) != 3 || got[0] != 1 {
		t.Fatalf("GetBytes() = %v, want length 3 with first byte 1", got)
	}

	store.SetString("s1", "upstream", "example.com:22")
	if str, ok := store.GetString("s1", "upstream"); !ok || str != "example.com:22" {
		t.Fatalf("GetString() = %q, ok=%v", str, ok)
	}

	store.SetValue("s1", "struct", &sample{Name: "foo"})
	if v, ok := store.GetValue("s1", "struct"); !ok {
		t.Fatalf("GetValue() ok=%v", ok)
	} else if s, ok := v.(*sample); !ok || s.Name != "foo" {
		t.Fatalf("GetValue() = %+v, ok=%v", s, ok)
	}

	store.Delete("s1", "secret", "upstream", "struct")
	if b := store.GetBytes("s1", "secret"); b != nil {
		t.Fatalf("Delete() did not remove secret, got %v", b)
	}
	if _, ok := store.GetString("s1", "upstream"); ok {
		t.Fatalf("Delete() did not remove upstream")
	}
	if _, ok := store.GetValue("s1", "struct"); ok {
		t.Fatalf("Delete() did not remove struct value")
	}
}

func TestSessionStoreSshError(t *testing.T) {
	store := NewSessionStore()

	if got := store.GetSshError("s1"); got != nil {
		t.Fatalf("GetSshError() unset = %v, want nil", got)
	}

	store.SetSshError("s1", "")
	got := store.GetSshError("s1")
	if got == nil {
		t.Fatalf("GetSshError() after SetSshError(\"\") = nil, want non-nil pointer")
	}
	if *got != "" {
		t.Fatalf("GetSshError() = %q, want empty string", *got)
	}

	store.SetSshError("s1", "boom")
	got = store.GetSshError("s1")
	if got == nil || *got != "boom" {
		t.Fatalf("GetSshError() = %v, want pointer to \"boom\"", got)
	}
}

func TestSessionStoreReset(t *testing.T) {
	store := NewSessionStore()

	store.SetSecret("s1", []byte("topsecret"))
	store.SetString("s1", KeyUpstream, "host:22")
	store.SetBytes("s1", "nonce", []byte("n"))
	store.SetSshError("s1", "boom")

	// keeperr=true: secret/upstream/extra cleared, ssh error preserved
	store.Reset("s1", true, "nonce")
	if got := store.GetSecret("s1"); got != nil {
		t.Fatalf("Reset(keeperr=true) left secret = %v", got)
	}
	if _, ok := store.GetString("s1", KeyUpstream); ok {
		t.Fatalf("Reset(keeperr=true) left upstream")
	}
	if got := store.GetBytes("s1", "nonce"); got != nil {
		t.Fatalf("Reset(keeperr=true) left nonce = %v", got)
	}
	if got := store.GetSshError("s1"); got == nil || *got != "boom" {
		t.Fatalf("Reset(keeperr=true) cleared ssh error, got %v", got)
	}

	// keeperr=false: ssh error also cleared
	store.SetSecret("s1", []byte("topsecret"))
	store.Reset("s1", false)
	if got := store.GetSecret("s1"); got != nil {
		t.Fatalf("Reset(keeperr=false) left secret = %v", got)
	}
	if got := store.GetSshError("s1"); got != nil {
		t.Fatalf("Reset(keeperr=false) left ssh error = %v", got)
	}
}
