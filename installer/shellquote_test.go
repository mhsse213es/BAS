package main

import "testing"

func TestShQuote_WrapsInSingleQuotes(t *testing.T) {
	got := shQuote("/usr/local/bin/bas-installer")
	want := "'/usr/local/bin/bas-installer'"
	if got != want {
		t.Fatalf("shQuote = %q, want %q", got, want)
	}
}

func TestShQuote_EscapesEmbeddedSingleQuote(t *testing.T) {
	// A naive quoter would let this close the quoted string early and
	// splice the rest onto the command line as live shell syntax.
	got := shQuote("it's a path")
	want := `'it'"'"'s a path'`
	if got != want {
		t.Fatalf("shQuote = %q, want %q", got, want)
	}
}

func TestShQuote_InjectionAttemptStaysOneArgument(t *testing.T) {
	malicious := "'; rm -rf / #"
	quoted := shQuote(malicious)
	// Every byte of the shell metacharacters must be inside quote
	// boundaries -- a bare, unescaped "; " sequence outside single quotes
	// would terminate the command and start a new one.
	if quoted != `''"'"'; rm -rf / #'` {
		t.Fatalf("shQuote(%q) = %q, unexpected escaping", malicious, quoted)
	}
}

func TestAppleScriptQuote_WrapsInDoubleQuotes(t *testing.T) {
	got := appleScriptQuote("hello")
	want := `"hello"`
	if got != want {
		t.Fatalf("appleScriptQuote = %q, want %q", got, want)
	}
}

func TestAppleScriptQuote_EscapesEmbeddedDoubleQuoteAndBackslash(t *testing.T) {
	got := appleScriptQuote(`say "hi" \ done`)
	want := `"say \"hi\" \\ done"`
	if got != want {
		t.Fatalf("appleScriptQuote = %q, want %q", got, want)
	}
}
