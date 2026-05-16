//go:build e2e

// Package e2e is the acceptance proof for the Temporal Web UI SSO story: a
// real temporalio/ui container, configured only via TEMPORAL_AUTH_* env vars,
// federates an OIDC login through a tempogate container to a mock Google IdP,
// receives a tempogate-signed JWT, and that JWT authenticates a gRPC call to a
// real temporal-frontend whose default authorizer is JWKS-backed by tempogate.
//
// Everything runs as containers on one Docker network so service-to-service
// and browser-to-service traffic share the same hostnames; the test process
// drives a containerised headless Chrome over its mapped DevTools port and
// talks gRPC over the frontend's mapped port. Gated behind `//go:build e2e`
// (and a dedicated CI job) so the fast unit suite stays fast.
package e2e

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcnetwork "github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.temporal.io/api/workflowservice/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Pinned images keep CI deterministic; override via env to bump without a
// code change. The Temporal auth env-var templating these rely on has been in
// the auto-setup config_template.yaml for many releases.
var (
	postgresImage = imageOr("E2E_POSTGRES_IMAGE", "postgres:16-alpine")
	temporalImage = imageOr("E2E_TEMPORAL_IMAGE", "temporalio/auto-setup:1.25.2")
	uiImage       = imageOr("E2E_TEMPORAL_UI_IMAGE", "temporalio/ui:2.32.0")
	chromeImage   = imageOr("E2E_CHROME_IMAGE", "chromedp/headless-shell:131.0.6778.86")
)

const (
	clientID     = "temporal-ui"
	clientSecret = "e2e-temporal-ui-confidential-secret"
	allowedEmail = "alice@example.com"
	deniedEmail  = "intruder@evil.test"

	tempogateIssuer = "http://tempogate:8000"
	uiCallback      = "http://temporal-ui:8080/auth/sso/callback"
	mockIssuer      = "http://mockgoogle:8080"
)

func imageOr(env, def string) string {
	if v := os.Getenv(env); v != "" {
		return v
	}
	return def
}

// stack holds the host-reachable endpoints the test process needs; everything
// else addresses peers by Docker network alias.
type stack struct {
	mockBaseURL  string // http://host:port to set the mock identity
	uiInternal   string // http://temporal-ui:8080 (browser, on the network)
	frontendAddr string // host:port for the gRPC client
	chromeWS     string // DevTools websocket for chromedp
}

func TestWebUISSO(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e: skipped in -short")
	}
	ctx := context.Background()
	st := setupStack(ctx, t)

	t.Run("happy path: SSO mints an admin JWT ready on first load, and gRPC ListNamespaces succeeds", func(t *testing.T) {
		st.setIdentity(t, allowedEmail, true)
		jwtStr := st.driveLoginAndExtractJWT(ctx, t)

		// (3) The JWT is ready on the first authenticated load: it was in the
		// session cookie the moment the browser landed back, with full perms.
		tok, err := jwt.ParseInsecure([]byte(jwtStr))
		require.NoError(t, err, "session cookie must carry a parseable tempogate JWT")

		iss, _ := tok.Issuer()
		require.Equal(t, tempogateIssuer, iss)
		aud, _ := tok.Audience()
		require.Contains(t, aud, clientID, "OIDC aud must be the UI's client_id")
		require.True(t, tok.Has("nonce"), "nonce must round-trip so the UI accepts the token")
		perms, ok := tok.Field("permissions")
		require.True(t, ok)
		require.Equal(t, []any{"*:admin"}, perms, "flat Hour-0 authz: full admin")
		sub, _ := tok.Subject()
		require.Equal(t, allowedEmail, sub)

		// (1) The same JWT authenticates a real gRPC call to temporal-frontend,
		// whose default authorizer is JWKS-backed by tempogate.
		client, conn := dialFrontend(t, st.frontendAddr)
		defer conn.Close()

		authed := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+jwtStr)
		resp, err := client.ListNamespaces(authed, &workflowservice.ListNamespacesRequest{PageSize: 10})
		require.NoError(t, err, "tempogate JWT must pass Temporal's default ClaimMapper")
		require.NotEmpty(t, resp.GetNamespaces(), "admin token should see namespaces")

		// Authorization is genuinely enforced: no token is rejected.
		_, err = client.ListNamespaces(ctx, &workflowservice.ListNamespacesRequest{PageSize: 10})
		require.Error(t, err, "frontend must reject an unauthenticated call")
		require.Contains(t,
			[]codes.Code{codes.Unauthenticated, codes.PermissionDenied},
			status.Code(err),
			"unexpected status: %v", err)
	})

	t.Run("disallowed domain bounces to 403", func(t *testing.T) {
		st.setIdentity(t, deniedEmail, true)
		body := st.driveLoginExpectingForbidden(ctx, t)
		require.Contains(t, body, "Access denied")
		require.Contains(t, body, "not in an allowed domain")
	})
}

// ---------- stack bring-up ----------

func setupStack(ctx context.Context, t *testing.T) *stack {
	t.Helper()
	root := repoRoot(t)

	net, err := tcnetwork.New(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = net.Remove(ctx) })
	netName := net.Name

	alias := func(name string) map[string][]string { return map[string][]string{netName: {name}} }

	// --- mock Google ---
	mock, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			FromDockerfile: testcontainers.FromDockerfile{
				Context: root, Dockerfile: "test/e2e/mockgoogle/Dockerfile", KeepImage: true,
			},
			Env:            map[string]string{"MOCK_ISSUER": mockIssuer},
			ExposedPorts:   []string{"8080/tcp"},
			Networks:       []string{netName},
			NetworkAliases: alias("mockgoogle"),
			WaitingFor:     wait.ForHTTP("/healthz").WithPort("8080/tcp").WithStartupTimeout(2 * time.Minute),
		},
		Started: true,
	})
	require.NoError(t, err, "mockgoogle")
	t.Cleanup(func() { _ = mock.Terminate(ctx) })
	mockBase := mappedHTTP(ctx, t, mock, "8080")

	// --- tempogate: migrate (one-shot) then serve, sharing a volume ---
	tgEnv := map[string]string{
		"HTTP__LISTENER":               "0.0.0.0:8000",
		"STATE__SQLITE__PATH":          "/state/state.db",
		"OIDC__ISSUER":                 tempogateIssuer,
		"OIDC__CLIENTS":                clientID + ":" + uiCallback,
		"OIDC__CLIENT_SECRETS":         clientID + ":" + clientSecret,
		"OIDC__ALLOWED_DOMAINS":        "example.com",
		"OIDC__GOOGLE__CLIENT_ID":      "tempogate-upstream",
		"OIDC__GOOGLE__CLIENT_SECRET":  "tempogate-upstream-secret",
		"OIDC__GOOGLE__AUTH_ENDPOINT":  mockIssuer + "/auth",
		"OIDC__GOOGLE__TOKEN_ENDPOINT": mockIssuer + "/token",
		"OIDC__GOOGLE__ISSUER_URL":     mockIssuer,
	}
	stateVol := fmt.Sprintf("tempogate-e2e-state-%d", time.Now().UnixNano())
	tgImage := testcontainers.FromDockerfile{Context: root, Dockerfile: "Dockerfile", KeepImage: true}

	migrate, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			FromDockerfile: tgImage,
			Cmd:            []string{"migrate"},
			Env:            tgEnv,
			User:           "0:0", // shared named volume; run as root so serve can reopen the file
			Mounts:         testcontainers.Mounts(testcontainers.VolumeMount(stateVol, "/state")),
			WaitingFor:     wait.ForExit().WithExitTimeout(2 * time.Minute),
		},
		Started: true,
	})
	require.NoError(t, err, "tempogate migrate")
	t.Cleanup(func() { _ = migrate.Terminate(ctx) })

	tempogate, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			FromDockerfile: tgImage,
			Cmd:            []string{"serve"},
			Env:            tgEnv,
			User:           "0:0",
			Mounts:         testcontainers.Mounts(testcontainers.VolumeMount(stateVol, "/state")),
			ExposedPorts:   []string{"8000/tcp"},
			Networks:       []string{netName},
			NetworkAliases: alias("tempogate"),
			WaitingFor: wait.ForHTTP("/readyz").WithPort("8000/tcp").
				WithStartupTimeout(2 * time.Minute),
		},
		Started: true,
	})
	require.NoError(t, err, "tempogate serve")
	t.Cleanup(func() { _ = tempogate.Terminate(ctx) })

	// --- postgres for Temporal ---
	pg, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image: postgresImage,
			Env: map[string]string{
				"POSTGRES_USER": "temporal", "POSTGRES_PASSWORD": "temporal", "POSTGRES_DB": "temporal",
			},
			Networks:       []string{netName},
			NetworkAliases: alias("db"),
			WaitingFor: wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).WithStartupTimeout(2 * time.Minute),
		},
		Started: true,
	})
	require.NoError(t, err, "postgres")
	t.Cleanup(func() { _ = pg.Terminate(ctx) })

	// --- temporal-frontend (auto-setup) with JWKS-backed default authorizer ---
	temporal, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image: temporalImage,
			Env: map[string]string{
				"DB": "postgres12", "DB_PORT": "5432",
				"POSTGRES_USER": "temporal", "POSTGRES_PWD": "temporal",
				"POSTGRES_SEEDS": "db", "DBNAME": "temporal",
				"BIND_ON_IP": "0.0.0.0", // frontend must be reachable off-loopback
				// Stock config_template.yaml templates the authorization block
				// from exactly these env vars.
				"TEMPORAL_JWT_KEY_SOURCE1":   tempogateIssuer + "/.well-known/jwks.json",
				"TEMPORAL_JWT_KEY_REFRESH":   "10s",
				"TEMPORAL_AUTH_AUTHORIZER":   "default",
				"TEMPORAL_AUTH_CLAIM_MAPPER": "default",
			},
			ExposedPorts:   []string{"7233/tcp"},
			Networks:       []string{netName},
			NetworkAliases: alias("temporal"),
			WaitingFor: wait.ForLog("Temporal server started").
				WithStartupTimeout(4 * time.Minute),
		},
		Started: true,
	})
	require.NoError(t, err, "temporal")
	t.Cleanup(func() { _ = temporal.Terminate(ctx) })

	// --- temporal-ui, configured only via TEMPORAL_AUTH_* ---
	ui, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image: uiImage,
			Env: map[string]string{
				"TEMPORAL_ADDRESS":            "temporal:7233",
				"TEMPORAL_UI_PORT":            "8080",
				"TEMPORAL_AUTH_ENABLED":       "true",
				"TEMPORAL_AUTH_TYPE":          "oidc",
				"TEMPORAL_AUTH_PROVIDER_URL":  tempogateIssuer,
				"TEMPORAL_AUTH_ISSUER_URL":    tempogateIssuer,
				"TEMPORAL_AUTH_CLIENT_ID":     clientID,
				"TEMPORAL_AUTH_CLIENT_SECRET": clientSecret,
				"TEMPORAL_AUTH_CALLBACK_URL":  uiCallback,
				"TEMPORAL_AUTH_SCOPES":        "openid email",
			},
			ExposedPorts:   []string{"8080/tcp"},
			Networks:       []string{netName},
			NetworkAliases: alias("temporal-ui"),
			WaitingFor: wait.ForHTTP("/").WithPort("8080/tcp").
				WithStartupTimeout(2 * time.Minute),
		},
		Started: true,
	})
	require.NoError(t, err, "temporal-ui")
	t.Cleanup(func() { _ = ui.Terminate(ctx) })

	// --- headless Chrome on the network so it resolves the aliases ---
	chrome, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image: chromeImage,
			Cmd: []string{
				"--remote-debugging-address=0.0.0.0", "--remote-debugging-port=9222",
				"--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage",
			},
			ExposedPorts:   []string{"9222/tcp"},
			Networks:       []string{netName},
			NetworkAliases: alias("chrome"),
			WaitingFor: wait.ForHTTP("/json/version").WithPort("9222/tcp").
				WithStartupTimeout(2 * time.Minute),
		},
		Started: true,
	})
	require.NoError(t, err, "chrome")
	t.Cleanup(func() { _ = chrome.Terminate(ctx) })

	return &stack{
		mockBaseURL:  mockBase,
		uiInternal:   "http://temporal-ui:8080",
		frontendAddr: mappedAddr(ctx, t, temporal, "7233"),
		chromeWS:     devtoolsWS(ctx, t, chrome),
	}
}

// ---------- browser flow ----------

// driveLoginAndExtractJWT runs the full SSO chain in headless Chrome and
// returns the tempogate JWT the Temporal UI stored in its session cookie.
func (s *stack) driveLoginAndExtractJWT(ctx context.Context, t *testing.T) string {
	t.Helper()
	browserCtx, cancel := s.browser(ctx, t)
	defer cancel()

	var rawCookie string
	err := chromedp.Run(browserCtx,
		network.Enable(),
		network.ClearBrowserCookies(),
		chromedp.Navigate(s.uiInternal+"/auth/sso?returnUrl=/namespaces"),
		chromedp.WaitVisible(`#approve`, chromedp.ByID), // mock Google consent screen
		chromedp.Click(`#approve`, chromedp.ByID),
		waitForCookie("user0", 90*time.Second, &rawCookie),
	)
	require.NoError(t, err, "SSO browser flow")
	require.NotEmpty(t, rawCookie, "Temporal UI must set the user session cookie")

	return decodeUITokenCookie(t, rawCookie)
}

// driveLoginExpectingForbidden runs the chain for a disallowed identity and
// returns the body text the browser ends on (tempogate's 403 page).
func (s *stack) driveLoginExpectingForbidden(ctx context.Context, t *testing.T) string {
	t.Helper()
	browserCtx, cancel := s.browser(ctx, t)
	defer cancel()

	var body string
	err := chromedp.Run(browserCtx,
		network.Enable(),
		network.ClearBrowserCookies(),
		chromedp.Navigate(s.uiInternal+"/auth/sso"),
		chromedp.WaitVisible(`#approve`, chromedp.ByID),
		chromedp.Click(`#approve`, chromedp.ByID),
		chromedp.Sleep(3*time.Second), // let the redirect chain settle on tempogate's 403
		chromedp.Text(`body`, &body, chromedp.ByQuery),
	)
	require.NoError(t, err, "forbidden browser flow")
	return body
}

func (s *stack) browser(ctx context.Context, t *testing.T) (context.Context, context.CancelFunc) {
	allocCtx, cancelAlloc := chromedp.NewRemoteAllocator(ctx, s.chromeWS)
	browserCtx, cancelBrowser := chromedp.NewContext(allocCtx)
	t.Cleanup(cancelBrowser)
	t.Cleanup(cancelAlloc)
	return browserCtx, func() { cancelBrowser(); cancelAlloc() }
}

// waitForCookie polls the cookie jar until the named cookie appears (login
// done) or the deadline passes. Joins multi-chunk session cookies (user0..N)
// in order, mirroring how the Temporal UI writes large tokens.
func waitForCookie(name string, timeout time.Duration, out *string) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		deadline := time.Now().Add(timeout)
		for {
			cookies, err := network.GetCookies().Do(ctx)
			if err == nil {
				chunks := map[string]string{}
				for _, c := range cookies {
					if strings.HasPrefix(c.Name, "user") {
						chunks[c.Name] = c.Value
					}
				}
				if _, ok := chunks[name]; ok {
					var b strings.Builder
					for i := 0; ; i++ {
						v, ok := chunks[fmt.Sprintf("user%d", i)]
						if !ok {
							break
						}
						b.WriteString(v)
					}
					*out = b.String()
					return nil
				}
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("e2e: cookie %q not set within %s", name, timeout)
			}
			time.Sleep(500 * time.Millisecond)
		}
	})
}

// decodeUITokenCookie reverses temporalio/ui-server's SetUser encoding:
// base64(JSON{AccessToken, IDToken, ...}). tempogate issues one token that is
// both, so either field is the JWT; IDToken is what go-oidc verified.
func decodeUITokenCookie(t *testing.T, raw string) string {
	t.Helper()
	if dec, err := url.QueryUnescape(raw); err == nil {
		raw = dec
	}
	b, err := base64.StdEncoding.DecodeString(raw)
	require.NoError(t, err, "user cookie must be base64")
	var u struct {
		AccessToken string `json:"AccessToken"`
		IDToken     string `json:"IDToken"`
	}
	require.NoError(t, json.Unmarshal(b, &u), "user cookie must be JSON")
	if u.IDToken != "" {
		return u.IDToken
	}
	return u.AccessToken
}

// ---------- helpers ----------

func (s *stack) setIdentity(t *testing.T, email string, verified bool) {
	t.Helper()
	form := url.Values{"email": {email}, "verified": {fmt.Sprintf("%t", verified)}}
	req, err := http.NewRequest(http.MethodPut, s.mockBaseURL+"/_control/identity",
		strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
}

func dialFrontend(t *testing.T, addr string) (workflowservice.WorkflowServiceClient, *grpc.ClientConn) {
	t.Helper()
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	return workflowservice.NewWorkflowServiceClient(conn), conn
}

func mappedAddr(ctx context.Context, t *testing.T, c testcontainers.Container, port string) string {
	t.Helper()
	host, err := c.Host(ctx)
	require.NoError(t, err)
	p, err := c.MappedPort(ctx, port+"/tcp")
	require.NoError(t, err)
	return fmt.Sprintf("%s:%s", host, p.Port())
}

func mappedHTTP(ctx context.Context, t *testing.T, c testcontainers.Container, port string) string {
	return "http://" + mappedAddr(ctx, t, c, port)
}

// devtoolsWS resolves the headless-shell DevTools websocket and rewrites its
// host to the mapped host:port the test process can reach.
func devtoolsWS(ctx context.Context, t *testing.T, c testcontainers.Container) string {
	t.Helper()
	base := mappedHTTP(ctx, t, c, "9222")
	var info struct {
		WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
	}
	require.Eventually(t, func() bool {
		resp, err := http.Get(base + "/json/version")
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		return json.NewDecoder(resp.Body).Decode(&info) == nil && info.WebSocketDebuggerURL != ""
	}, 60*time.Second, time.Second, "DevTools endpoint never came up")

	u, err := url.Parse(info.WebSocketDebuggerURL)
	require.NoError(t, err)
	mapped, err := url.Parse(base)
	require.NoError(t, err)
	u.Host = mapped.Host
	return u.String()
}

func repoRoot(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join("..", ".."))
	require.NoError(t, err)
	return abs
}
