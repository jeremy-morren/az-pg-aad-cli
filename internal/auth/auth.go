// Package auth obtains Entra tokens for Azure Database for PostgreSQL and works out
// which Postgres role a token belongs to.
package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

const (
	// DatabaseScope is the Entra scope for Azure Database for PostgreSQL.
	DatabaseScope = "https://ossrdbms-aad.database.windows.net/.default"
	// GraphScope is the Microsoft Graph scope used for username lookups.
	GraphScope = "https://graph.microsoft.com/.default"
	// GraphBaseURL is the Microsoft Graph v1.0 endpoint.
	GraphBaseURL = "https://graph.microsoft.com/v1.0"
	// Grace is how long before expiry a stored token is replaced.
	Grace = 10 * time.Minute
)

// NewCredential returns the credential used by --azure: env/service principal, workload
// identity, managed identity, az CLI, azd — whichever is available.
func NewCredential() (azcore.TokenCredential, error) {
	return azidentity.NewDefaultAzureCredential(nil)
}

// Token is an access token and when it expires.
type Token struct {
	Value   string
	Expires time.Time
}

// GetToken fetches a token for scope. The expiry comes from the credential, falling back
// to the token's exp claim when the credential doesn't supply a usable one.
func GetToken(ctx context.Context, cred azcore.TokenCredential, scope string, now time.Time) (Token, error) {
	at, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{scope}})
	if err != nil {
		return Token{}, err
	}
	exp := at.ExpiresOn
	if !exp.After(now) {
		if claims, err := Claims(at.Token); err == nil {
			if e, ok := claims["exp"].(float64); ok {
				exp = time.Unix(int64(e), 0)
			}
		}
	}
	return Token{Value: at.Token, Expires: exp.UTC()}, nil
}

// NeedsRefresh reports whether a token expiring at exp should be replaced at now.
func NeedsRefresh(exp, now time.Time) bool {
	return !now.Add(Grace).Before(exp)
}

// Claims decodes a JWT payload without validating it (the server validates the token;
// we only read claims to pick a username).
func Claims(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("token is not a JWT")
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return nil, fmt.Errorf("token payload: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(b, &claims); err != nil {
		return nil, fmt.Errorf("token payload: %w", err)
	}
	return claims, nil
}

func claimString(claims map[string]any, names ...string) string {
	for _, n := range names {
		if s, ok := claims[n].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// isUserToken reports whether the token was issued to a signed-in user (delegated)
// rather than an application (managed identity / service principal).
func isUserToken(claims map[string]any) bool {
	if t, ok := claims["idtyp"].(string); ok {
		return t == "user"
	}
	_, delegated := claims["scp"]
	return delegated
}

// fallbackClaims are tried, in order, when Graph can't be asked.
var fallbackClaims = []string{"upn", "preferred_username", "unique_name", "email"}

// Resolver works out the Postgres role name for a database token.
type Resolver struct {
	Cred      azcore.TokenCredential
	HTTP      *http.Client
	GraphBase string
	Now       func() time.Time
	// Warn receives warnings (written to stderr by the CLI).
	Warn func(string)
}

// Username returns the role name for dbToken:
//  1. user token: Graph /me userPrincipalName (correct for guests' #EXT# UPNs);
//     if that fails, the upn claim, then other name claims, with a warning.
//  2. app token: Graph servicePrincipals/{oid} displayName (a service principal can
//     read itself without Graph permissions); if that fails, the name claims.
//  3. nothing found: an error listing the claims present.
func (r Resolver) Username(ctx context.Context, dbToken string) (string, error) {
	claims, err := Claims(dbToken)
	if err != nil {
		return "", err
	}
	var name string
	var graphErr error
	if isUserToken(claims) {
		name, graphErr = r.graphString(ctx, "/me?$select=userPrincipalName", "userPrincipalName")
	} else if oid := claimString(claims, "oid"); oid != "" {
		name, graphErr = r.graphString(ctx, "/servicePrincipals/"+url.PathEscape(oid)+"?$select=displayName", "displayName")
	} else {
		graphErr = errors.New("token has no oid claim")
	}
	if graphErr == nil && name != "" {
		return name, nil
	}
	if fb := claimString(claims, fallbackClaims...); fb != "" {
		if r.Warn != nil {
			r.Warn(fmt.Sprintf("could not look up the username in Microsoft Graph (%v); using %q from the token. Pass --username if that isn't the Postgres role name.", graphErr, fb))
		}
		return fb, nil
	}
	keys := make([]string, 0, len(claims))
	for k := range claims {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return "", fmt.Errorf("could not determine the Postgres username: Microsoft Graph lookup failed (%v) and the token has no username claim (claims present: %s). Pass --username with the Postgres role name",
		graphErr, strings.Join(keys, ", "))
}

func (r Resolver) graphString(ctx context.Context, path, field string) (string, error) {
	now := time.Now
	if r.Now != nil {
		now = r.Now
	}
	tok, err := GetToken(ctx, r.Cred, GraphScope, now())
	if err != nil {
		return "", fmt.Errorf("graph token: %w", err)
	}
	base := r.GraphBase
	if base == "" {
		base = GraphBaseURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+tok.Value)
	req.Header.Set("Accept", "application/json")
	client := r.HTTP
	if client == nil {
		client = &http.Client{Timeout: time.Minute}
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s: %s", path, resp.Status)
	}
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		return "", fmt.Errorf("GET %s: %w", path, err)
	}
	s, _ := obj[field].(string)
	if s == "" {
		return "", fmt.Errorf("GET %s: no %s in response", path, field)
	}
	return s, nil
}
