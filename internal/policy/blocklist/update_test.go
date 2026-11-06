package blocklist

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFetchConditional(t *testing.T) {
	var etag = `"v1"`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		_, _ = w.Write([]byte("0.0.0.0 ads.example\n"))
	}))
	defer srv.Close()
	f := &Fetcher{AllowHTTP: true, AllowPrivate: true}
	got, err := f.Fetch(context.Background(), srv.URL, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if got.NotModified || !strings.Contains(string(got.Body), "ads.example") {
		t.Fatalf("first = %+v", got)
	}
	again, err := f.Fetch(context.Background(), srv.URL, got.ETag, got.LastModified)
	if err != nil {
		t.Fatal(err)
	}
	if !again.NotModified {
		t.Fatalf("second = %+v", again)
	}
}

func TestFetchRejectsHTTPAndPrivateByDefault(t *testing.T) {
	f := &Fetcher{}
	if _, err := f.Fetch(context.Background(), "http://example.com/x", "", ""); err == nil {
		t.Fatal("http accepted")
	}
	if _, err := f.Fetch(context.Background(), "https://127.0.0.1/x", "", ""); err == nil {
		t.Fatal("loopback accepted")
	}
}

// A public name that resolves to a private address must be refused where the
// connection is made. Redirects dial through the same check.
func TestFetchChecksTheAddressItDials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ads.example\n"))
	}))
	defer srv.Close()
	// localhost is a name, so the early literal check can't catch it.
	u := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	f := &Fetcher{AllowHTTP: true}
	if _, err := f.Fetch(context.Background(), u, "", ""); err == nil || !strings.Contains(err.Error(), "private") {
		t.Fatalf("dial to loopback by name: %v", err)
	}
}
