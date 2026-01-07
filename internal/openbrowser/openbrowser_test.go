package openbrowser

import "testing"

func TestPromptPipeOpensAndNotifies(t *testing.T) {
	origOpen := openURL
	defer func() { openURL = origOpen }()

	var opened string
	openURL = func(u string) error {
		opened = u
		return nil
	}

	var instruction string
	client := func(_, instr, _ string, _ bool) (string, error) {
		instruction = instr
		return "", nil
	}

	PromptPipe(client, "https://example.com", "abc")

	wantURL := "https://example.com/pipe/abc"
	if opened != wantURL {
		t.Fatalf("openURL called with %q, want %q", opened, wantURL)
	}

	wantInstruction := "please open https://example.com/pipe/abc with your browser to verify (timeout 1m)"
	if instruction != wantInstruction {
		t.Fatalf("instruction = %q, want %q", instruction, wantInstruction)
	}
}
