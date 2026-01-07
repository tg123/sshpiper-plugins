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
