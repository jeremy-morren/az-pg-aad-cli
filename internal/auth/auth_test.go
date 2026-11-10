package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

func jwt(claims map[string]any) string {
	b, _ := json.Marshal(claims)
	e := base64.RawURLEncoding
	return e.EncodeToString([]byte(`{"alg":"none"}`)) + "." + e.EncodeToString(b) + ".sig"
}

type cred struct{ err error }

func (c cred) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	if c.err != nil {
		return azcore.AccessToken{}, c.err
	}
	return azcore.AccessToken{Token: "graph-token", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

func TestNeedsRefresh(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		left time.Duration
		want bool
	}{{time.Hour, false}, {10*time.Minute + time.Second, false}, {10 * time.Minute, true}, {time.Minute, true}, {-time.Hour, true}} {
		if got := NeedsRefresh(now.Add(c.left), now); got != c.want {
			t.Errorf("%v left: got %v want %v", c.left, got, c.want)
		}
	}
}

func TestGetTokenFallsBackToExpClaim(t *testing.T) {
	now := time.Now()
	exp := now.Add(42 * time.Minute).Truncate(time.Second)
	c := expCred{token: jwt(map[string]any{"exp": exp.Unix()})}
	tok, err := GetToken(context.Background(), c, DatabaseScope, now)
	if err != nil || !tok.Expires.Equal(exp.UTC()) {
		t.Fatalf("%v %v want %v", tok.Expires, err, exp)
	}
}

type expCred struct{ token string }

func (c expCred) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: c.token}, nil // no ExpiresOn
}

func graph(t *testing.T, status int, body map[string]any, seen *string) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*seen = r.URL.Path + "?" + r.URL.RawQuery
		if r.Header.Get("Authorization") != "Bearer graph-token" {
			t.Errorf("missing graph token: %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestUsername(t *testing.T) {
	user := jwt(map[string]any{"idtyp": "user", "scp": "user_impersonation", "upn": "member@contoso.com", "oid": "u-oid"})
	guest := jwt(map[string]any{"idtyp": "user", "scp": "x", "unique_name": "live.com#guest@outlook.com", "email": "guest@outlook.com"})
	app := jwt(map[string]any{"idtyp": "app", "oid": "11111111-2222-3333-4444-555555555555", "appid": "a"})
	appNoName := jwt(map[string]any{"oid": "11111111-2222-3333-4444-555555555555"})

	cases := []struct {
		name     string
		token    string
		status   int
		body     map[string]any
		credErr  error
		want     string
		wantPath string
		wantWarn bool
		wantErr  string
	}{
		{"member via /me", user, 200, map[string]any{"userPrincipalName": "member@contoso.com"}, nil,
			"member@contoso.com", "/me?$select=userPrincipalName", false, ""},
		{"guest via /me gets #EXT# UPN", guest, 200, map[string]any{"userPrincipalName": "guest_outlook.com#EXT#@contoso.onmicrosoft.com"}, nil,
			"guest_outlook.com#EXT#@contoso.onmicrosoft.com", "/me?$select=userPrincipalName", false, ""},
		{"/me fails -> upn claim", user, 403, map[string]any{}, nil,
			"member@contoso.com", "/me?$select=userPrincipalName", true, ""},
		{"/me fails, guest -> unique_name", guest, 500, map[string]any{}, nil,
			"live.com#guest@outlook.com", "/me?$select=userPrincipalName", true, ""},
		{"app via servicePrincipals", app, 200, map[string]any{"displayName": "my-identity"}, nil,
			"my-identity", "/servicePrincipals/11111111-2222-3333-4444-555555555555?$select=displayName", false, ""},
		{"app lookup fails, no claims", appNoName, 404, map[string]any{}, nil,
			"", "/servicePrincipals/11111111-2222-3333-4444-555555555555?$select=displayName", false, "Pass --username"},
		{"graph token unavailable -> upn", user, 200, nil, errors.New("no graph"),
			"member@contoso.com", "", true, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var seen string
			srv := graph(t, c.status, c.body, &seen)
			var warned bool
			r := Resolver{Cred: cred{c.credErr}, GraphBase: srv.URL, Warn: func(string) { warned = true }}
			got, err := r.Username(context.Background(), c.token)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("err %v, want %q", err, c.wantErr)
				}
				return
			}
			if err != nil || got != c.want {
				t.Fatalf("got %q %v, want %q", got, err, c.want)
			}
			if seen != c.wantPath {
				t.Errorf("graph path %q, want %q", seen, c.wantPath)
			}
			if warned != c.wantWarn {
				t.Errorf("warned=%v want %v", warned, c.wantWarn)
			}
		})
	}
}
