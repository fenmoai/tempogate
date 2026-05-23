//go:build e2e

// This file is the acceptance proof for the remote-shell story: a real
// `tempogate login --device` binary runs the RFC 8628 device authorization
// grant against a tempogate container that federates to a mock Google,
// drives the templated verification UI in a headless Chromium, persists the
// issued JWT, and that JWT authenticates a real gRPC call to a
// temporal-frontend whose default authorizer is JWKS-backed by tempogate.
//
// The headless-shell + tempogate-binary cliclient container is the same one
// the loopback proof uses: the CLI subprocess and the browser that walks the
// verification UI share one network namespace, exactly like a developer
// laptop. Three OIDC client_ids are registered (in addition to the loopback
// proof's `tempogate-cli`): `tempogate-device` (the public CLI client),
// `tempogate-device-ui` (the confidential internal client tempogate uses to
// bounce the verification page through its own /authorize chain), plus a
// signing key for the verification-page session cookie.
//
// Negative-path coverage is table-driven: a Deny click and a short-deadline
// no-driver timeout assert that the corresponding RFC 8628 §3.5 terminal
// responses surface on the subprocess's stderr.
package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/stretchr/testify/require"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
	"go.temporal.io/api/workflowservice/v1"
	"google.golang.org/grpc/metadata"

	"github.com/fenmoai/tempogate/cli"
	"github.com/fenmoai/tempogate/oidc"
)

const (
	deviceClientID       = "tempogate-device"
	deviceUIClientID     = "tempogate-device-ui"
	deviceUIClientSecret = "e2e-device-ui-confidential-secret"

	cliDeviceTokenFile  = "/tmp/tg-device-token.json"
	cliDeviceStdoutFile = "/tmp/tempogate-device.stdout"
	cliDeviceStderrFile = "/tmp/tempogate-device.stderr"
)

// userCodeDisplayPattern matches the dashed `XXXX-XXXX` display form the CLI
// prints and the confirm page renders. Letters and digits are the RFC 8628
// §6.1 base20 + 4-digit alphabet tempogate's user-code generator uses.
var userCodeDisplayPattern = regexp.MustCompile(`[BCDFGHJKLMNPQRSTVWXZ3479]{4}-[BCDFGHJKLMNPQRSTVWXZ3479]{4}`)

// verificationURIPattern matches the verification_uri_complete the CLI prints
// on stderr after a successful POST /device_authorization. The dashed
// user_code in the query is URL-safe; the path is /device under whatever the
// tempogate issuer is.
var verificationURIPattern = regexp.MustCompile(`https?://\S+/device\?user_code=[A-Z0-9%-]+`)

func TestCLIDeviceLogin(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e: skipped in -short")
	}
	ctx := context.Background()
	st := setupCLIStack(ctx, t)

	(&stack{mockBaseURL: st.mockBaseURL}).setIdentity(t, allowedEmail, true)

	t.Run("happy path: approve in the UI, JWT authenticates against temporal-frontend", func(t *testing.T) {
		loginDone := make(chan loginResult, 1)
		st.spawnDeviceLogin(ctx, t, loginDone,
			cliDeviceStdoutFile, cliDeviceStderrFile,
			"--issuer", tempogateIssuer,
			"--token-file", cliDeviceTokenFile,
			"--device-poll-deadline", "2m",
		)

		verificationURI, userCode := st.waitDevicePrompt(ctx, t, cliDeviceStderrFile)
		require.Truef(t,
			strings.HasPrefix(verificationURI, tempogateIssuer+oidc.DevicePath+"?user_code="),
			"verification_uri_complete must point at tempogate's /device with a pre-filled user_code, got %q",
			verificationURI)
		require.Regexp(t, userCodeDisplayPattern, userCode,
			"user_code must be a dashed base24 XXXX-XXXX")

		st.driveDeviceDecision(ctx, t, verificationURI, "button.primary")

		select {
		case r := <-loginDone:
			require.NoError(t, r.err, "tempogate login --device exec")
			require.Equalf(t, 0, r.code,
				"tempogate login --device must exit 0; stderr:\n%s",
				st.readContainerFile(ctx, t, cliDeviceStderrFile))
		case <-time.After(3 * time.Minute):
			t.Fatal("e2e: tempogate login --device did not complete after approve")
		}

		// --- the persisted token file: 0600, a parseable tempogate JWT.
		require.Equal(t, "600", st.statMode(ctx, t, cliDeviceTokenFile),
			"the device-flow token file must be -rw------- like the loopback path")
		tok := st.readTokenFrom(ctx, t, cliDeviceTokenFile)
		require.NotEmpty(t, tok.AccessToken)
		require.NotEmpty(t, tok.RefreshToken, "device flow must persist a refresh token for `tempogate token`")
		require.True(t, tok.ExpiresAt.After(time.Now().Add(3*time.Hour)),
			"a freshly minted device-flow access token should be ~4h out, same as loopback")
		assertTempogateJWT(t, tok.AccessToken)

		// --- the JWT authenticates a real gRPC call against the JWKS-backed
		// temporal-frontend, identical contract to the loopback flow.
		client, conn := dialFrontend(t, st.frontendAddr)
		defer func() { _ = conn.Close() }()

		authed := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+tok.AccessToken)
		resp, err := client.ListNamespaces(authed, &workflowservice.ListNamespacesRequest{PageSize: 10})
		require.NoError(t, err, "device-flow JWT must pass Temporal's default ClaimMapper")
		require.NotEmpty(t, resp.GetNamespaces(), "admin token should see namespaces")
	})

	t.Run("negative paths", func(t *testing.T) {
		cases := []struct {
			name             string
			extraFlags       []string
			drive            func(ctx context.Context, t *testing.T, s *cliStack, verificationURI string)
			wantStderrSubstr string
		}{
			{
				// User reaches the confirm page, reads the code, decides not to
				// approve. RFC 8628 §3.5 access_denied; cli surfaces it as
				// ErrUserDenied = "user denied the device authorization".
				name:             "user clicks Deny on the confirm page",
				extraFlags:       []string{"--device-poll-deadline", "2m"},
				drive:            denyOnConfirm,
				wantStderrSubstr: "user denied",
			},
			{
				// CLI gives up before the user ever loads the verification URL.
				// With --device-poll-deadline=3s and the server's 5s default
				// interval, the deadline trips after the very first poll; the
				// cli surfaces ErrPollDeadlineExceeded =
				// "polling deadline exceeded".
				name:             "polling deadline exceeded before user approves",
				extraFlags:       []string{"--device-poll-deadline", "3s"},
				drive:            nil,
				wantStderrSubstr: "polling deadline exceeded",
			},
		}

		for _, tc := range cases {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				slug := strings.ReplaceAll(strings.Map(slugSafe, tc.name), " ", "-")
				stdout := fmt.Sprintf("/tmp/tg-device-neg-%s.stdout", slug)
				stderr := fmt.Sprintf("/tmp/tg-device-neg-%s.stderr", slug)
				tokFile := fmt.Sprintf("/tmp/tg-device-neg-%s.json", slug)

				args := append([]string{
					"--issuer", tempogateIssuer,
					"--token-file", tokFile,
				}, tc.extraFlags...)

				loginDone := make(chan loginResult, 1)
				st.spawnDeviceLogin(ctx, t, loginDone, stdout, stderr, args...)

				if tc.drive != nil {
					verificationURI, _ := st.waitDevicePrompt(ctx, t, stderr)
					tc.drive(ctx, t, st, verificationURI)
				}

				select {
				case r := <-loginDone:
					require.NoError(t, r.err, "tempogate login --device exec (%s)", tc.name)
					stderrBody := st.readContainerFile(ctx, t, stderr)
					require.NotEqualf(t, 0, r.code,
						"tempogate login --device must exit non-zero for %q; stderr:\n%s",
						tc.name, stderrBody)
					require.Containsf(t, stderrBody, tc.wantStderrSubstr,
						"stderr must mention %q for %q; got:\n%s",
						tc.wantStderrSubstr, tc.name, stderrBody)
				case <-time.After(2 * time.Minute):
					t.Fatalf("e2e: tempogate login --device (%s) did not exit", tc.name)
				}
			})
		}
	})
}

// ---------- cli-side helpers ----------

// spawnDeviceLogin starts `tempogate login --device` inside the cliclient
// container with stdout / stderr redirected to files on tmpfs so the test can
// poll the human-facing prompt and assert the printed access token without
// racing the live subprocess. The Exec call blocks until the binary exits;
// the goroutine reports the exit code on done so the caller can both drive
// the verification UI and wait for the subprocess in the same select.
func (s *cliStack) spawnDeviceLogin(ctx context.Context, t *testing.T, done chan<- loginResult, stdoutPath, stderrPath string, extraArgs ...string) {
	t.Helper()
	_, _, _ = s.client.Exec(ctx,
		[]string{"sh", "-c", "rm -f " + stdoutPath + " " + stderrPath},
		tcexec.Multiplexed(),
	)
	args := append([]string{"tempogate", "login", "--device"}, extraArgs...)
	cmd := shellQuote(args) + " > " + stdoutPath + " 2> " + stderrPath
	go func() {
		code, _, err := s.client.Exec(ctx,
			[]string{"sh", "-c", cmd},
			tcexec.Multiplexed(),
		)
		done <- loginResult{code: code, err: err}
	}()
}

// waitDevicePrompt polls stderrPath until the CLI's RFC 8628 §3.3 prompt has
// both the verification_uri_complete and a dashed user_code visible. The
// prompt is published in one Fprintf call so a single read is normally
// enough, but the polling guards against the goroutine that spawned the
// subprocess racing the file's first write.
func (s *cliStack) waitDevicePrompt(ctx context.Context, t *testing.T, stderrPath string) (verificationURI, userCode string) {
	t.Helper()
	require.Eventually(t, func() bool {
		body := s.readContainerFile(ctx, t, stderrPath)
		uri := verificationURIPattern.FindString(body)
		code := userCodeDisplayPattern.FindString(body)
		if uri == "" || code == "" {
			return false
		}
		verificationURI = uri
		userCode = code
		return true
	}, 90*time.Second, 250*time.Millisecond,
		"tempogate login --device never printed the user_code + verification_uri_complete on stderr")
	return
}

// readContainerFile cats a file inside the cliclient container and returns
// its body. Missing files return "" — the polling helpers above use the
// empty return as their "keep waiting" signal.
func (s *cliStack) readContainerFile(ctx context.Context, t *testing.T, path string) string {
	t.Helper()
	code, r, err := s.client.Exec(ctx,
		[]string{"sh", "-c", "cat " + path + " 2>/dev/null || true"},
		tcexec.Multiplexed(),
	)
	if err != nil || code != 0 {
		return ""
	}
	b, _ := io.ReadAll(r)
	return string(b)
}

// readTokenFrom pulls the JSON token file out of the container and decodes
// it. Mirrors readToken but takes the path explicitly so multiple
// concurrent device-flow scenarios can keep separate token files inside the
// same container.
func (s *cliStack) readTokenFrom(ctx context.Context, t *testing.T, path string) cli.Token {
	t.Helper()
	rc, err := s.client.CopyFileFromContainer(ctx, path)
	require.NoError(t, err)
	defer func() { _ = rc.Close() }()
	var tok cli.Token
	require.NoError(t, json.NewDecoder(rc).Decode(&tok))
	return tok
}

// driveDeviceDecision walks the headless Chrome through the full RFC 8628
// §3.3 verification UI: load the verification_uri_complete (which pre-fills
// the user_code), submit the entry form (POST /device → 303 /authorize →
// mock Google consent → /callback/google → /device/sso-callback →
// /device/confirm), then click the selector on the confirm page (Approve =
// button.primary, Deny = button.danger).
//
// The entry-form transition uses SendKeys + KeyEnter rather than Click on
// the submit button: a real keypress on the input is treated by chrome as
// a trusted user gesture and triggers the form's default submit handler
// natively, which is more resilient to the input's HTML5 pattern/required
// validators than a synthetic Click event in headless-shell.
func (s *cliStack) driveDeviceDecision(ctx context.Context, t *testing.T, verificationURI, decisionSelector string) {
	t.Helper()
	allocCtx, cancelAlloc := chromedp.NewRemoteAllocator(ctx, s.chromeWS)
	t.Cleanup(cancelAlloc)
	bctx, cancelBrowser := chromedp.NewContext(allocCtx)
	t.Cleanup(cancelBrowser)

	require.NoErrorf(t, chromedp.Run(bctx,
		// /device — verification URL pre-fills the user_code; press Enter
		// on the input to submit the form. SendKeys + KeyEnter goes
		// through CDP's Input.dispatchKeyEvent which the browser treats as
		// a trusted keypress: the form's default submit handler fires
		// natively, bypassing the input's HTML5 pattern/required
		// validators that intermittently swallow a synthetic Click in
		// this chromedp v0.15.1 / headless-shell 131 combination.
		chromedp.Navigate(verificationURI),
		chromedp.WaitVisible(`#user_code`, chromedp.ByID),
		chromedp.SendKeys(`#user_code`, "\r", chromedp.ByID),
		// Mock upstream consent — click Approve. The redirect chain that
		// gets us here (POST /device → 303 /authorize → 302 mock /auth)
		// settles inside this WaitVisible; chromedp polls until #approve
		// renders.
		chromedp.WaitVisible(`#approve`, chromedp.ByID),
		chromedp.Click(`#approve`, chromedp.ByID),
		// /device/confirm — click Approve or Deny per the scenario. The
		// SSO callback bounce (mock /auth/approve → 302 /callback/google →
		// 302 /device/sso-callback → 303 /device/confirm) again settles
		// inside this WaitVisible.
		chromedp.WaitVisible(decisionSelector, chromedp.ByQuery),
		chromedp.Click(decisionSelector, chromedp.ByQuery),
		chromedp.WaitReady(`body`, chromedp.ByQuery),
	), "drive device verification UI (selector=%s)", decisionSelector)
}

// denyOnConfirm is the table-driven adapter for the Deny scenario. The
// happy-path Approve case calls driveDeviceDecision directly with
// "button.primary"; this adapter exists so the negative table can list
// driver functions of identical shape without exposing the selector to the
// scenarios slice.
func denyOnConfirm(ctx context.Context, t *testing.T, s *cliStack, verificationURI string) {
	s.driveDeviceDecision(ctx, t, verificationURI, "button.danger")
}

// shellQuote single-quotes each arg so the assembled `sh -c` string is safe
// for whitespace, quotes, and shell metacharacters. The args here are flag
// values the test controls (durations, paths, URLs), so the quoting is more
// a discipline than a security boundary — but doing it once here keeps the
// spawnDeviceLogin call sites free of error-prone string-concat.
func shellQuote(args []string) string {
	var b strings.Builder
	for i, a := range args {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteByte('\'')
		b.WriteString(strings.ReplaceAll(a, "'", `'\''`))
		b.WriteByte('\'')
	}
	return b.String()
}

// slugSafe maps a test-name character to a filesystem-safe stand-in. The
// negative-path subtests write their stdout/stderr/token files into /tmp
// inside the cliclient; the slug feeds the path so each scenario gets its
// own files without leaking shell metacharacters from t.Run names.
func slugSafe(r rune) rune {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-':
		return r
	case r == ' ':
		return '-'
	default:
		return -1
	}
}
