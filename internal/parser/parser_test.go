package parser

import (
	"reflect"
	"testing"

	"github.com/August26/proxycheck-go/internal/model"
)

func TestParseProxyLine_Simple(t *testing.T) {
	line := "1.2.3.4:8080"
	res, err := parseProxyLine(line)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if res.Host != "1.2.3.4" || res.Port != 8080 {
		t.Fatalf("bad parse: %#v", res)
	}
	if res.Username != "" || res.Password != "" {
		t.Fatalf("should not have auth: %#v", res)
	}
}

func TestParseProxyLine_WithAuthColonStyle(t *testing.T) {
	line := "5.6.7.8:1080:user:pass"
	res, err := parseProxyLine(line)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	want := model.ProxyInput{
		Host:     "5.6.7.8",
		Port:     1080,
		Username: "user",
		Password: "pass",
		Type:     "",
		Raw:      line,
	}
	if !reflect.DeepEqual(stripRaw(res), stripRaw(want)) {
		t.Fatalf("got %#v want %#v", res, want)
	}
}

func TestParseProxyLine_WithAuthAtStyle(t *testing.T) {
	line := "user:pass@9.9.9.9:3128"
	res, err := parseProxyLine(line)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if res.Host != "9.9.9.9" || res.Port != 3128 {
		t.Fatalf("bad host/port parse: %#v", res)
	}
	if res.Username != "user" || res.Password != "pass" {
		t.Fatalf("bad auth parse: %#v", res)
	}
}

func TestParseProxyLine_Invalid(t *testing.T) {
	bad := "not a proxy line"
	_, err := parseProxyLine(bad)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
}

// helper to compare ignoring Raw because Raw is just debug info.
func stripRaw(in model.ProxyInput) model.ProxyInput {
	in.Raw = ""
	return in
}

