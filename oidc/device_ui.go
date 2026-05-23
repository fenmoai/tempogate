package oidc

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
)

const (
	// DevicePathSegment is the verification-page path tempogate's own
	// /device_authorization response advertises (see DevicePath). The UI
	// handlers below share the same base so a single embedded HTML form can
	// post back to itself without re-deriving the URL.
	DevicePathSegment = DevicePath

	// DeviceSSOCallbackPath is the loopback redirect_uri the internal
	// tempogate-device-ui client registers under. It must match the value
	// operators configure for that client in OIDC__CLIENTS; the registrar's
	// graph-time validation rejects a deployment where they have drifted.
	DeviceSSOCallbackPath = DevicePath + "/sso-callback"

	// DeviceConfirmPath renders the approve/deny prompt after the session
	// cookie has been issued. Reached either directly (when a session is
	// already present) or via DeviceSSOCallbackPath (when one had to be
	// minted through the upstream IdP bounce).
	DeviceConfirmPath = DevicePath + "/confirm"

	// DeviceApprovePath and DeviceDenyPath are the CSRF-protected POST
	// targets the confirm-page form submits to.
	DeviceApprovePath = DevicePath + "/approve"
	DeviceDenyPath    = DevicePath + "/deny"

	// DefaultInternalDeviceUIClientID is the client_id tempogate registers
	// for its own verification-UI side. It is operator-configured in
	// OIDC__CLIENTS / OIDC__CLIENT_SECRETS rather than auto-injected so
	// active verification sessions survive a rolling restart.
	DefaultInternalDeviceUIClientID = "tempogate-device-ui"

	// deviceStateTTL bounds how long the signed bounce state remains
	// honoured after a /idp/device POST. Short enough that an abandoned
	// Google round-trip cannot be resumed much later; longer than the
	// upstream session_ttl so a slow but live SSO completion is not
	// rejected by the wrong clock.
	deviceStateTTL = 10 * time.Minute

	// deviceStateNonceBytes is the entropy carried in the bounce state so
	// two concurrent device flows can never produce identical signed states
	// (the HMAC alone would collide for identical {user_code, exp} pairs).
	deviceStateNonceBytes = 16
)

//go:embed templates/*.html
var deviceUITemplatesFS embed.FS

// devicePages enumerates the template files that compose each rendered page.
// Each set is loaded as base.html plus the page-specific child; the child
// supplies `title` and `content` blocks that the base layout pulls in.
var devicePages = map[string]string{
	"enter":    "device_enter.html",
	"confirm":  "device_confirm.html",
	"approved": "device_approved.html",
	"denied":   "device_denied.html",
	"error":    "device_error.html",
}

// ErrInternalDeviceUIClientMissing is returned by NewDeviceUI when the
// operator-managed tempogate-device-ui client is not present in the
// ClientRegistry. The registrar wraps it into an actionable graph-time
// failure so a deployment never silently lands the verification UI on top
// of an unconfigured internal client.
var ErrInternalDeviceUIClientMissing = errors.New("oidc: internal device-ui client not registered in OIDC__CLIENTS")

// ErrInternalDeviceUIClientNotConfidential is returned by NewDeviceUI when
// the internal client is registered without a secret. The verification
// bounce authenticates the client at /token via that secret, so a public
// registration would silently break the round-trip.
var ErrInternalDeviceUIClientNotConfidential = errors.New("oidc: internal device-ui client must be confidential (set its secret in OIDC__CLIENT_SECRETS)")

// DeviceUI serves the human-side of the RFC 8628 §3.3 verification flow:
// the user_code entry form, the SSO bounce through tempogate's own
// /idp/authorize chain (acting as the internal tempogate-device-ui client),
// and the CSRF-protected Approve / Deny prompt that flips the device_codes
// row the CLI is polling.
type DeviceUI struct {
	devices              DeviceCodeStore
	sessions             *SessionManager
	clients              ClientRegistry
	signingKey           []byte
	issuer               string
	internalClientID     string
	internalClientSecret string
	tokenURL             string
	httpClient           *http.Client
	now                  func() time.Time
	newStateNonce        func() (string, error)
	pages                map[string]*template.Template
}

// DeviceUIOption configures a DeviceUI at construction. Every seam a test
// might want to control — clock, state nonce, internal client id, token URL,
// HTTP client — is reachable here so production code stays on the defaults.
type DeviceUIOption func(*DeviceUI)

// WithDeviceUIClock swaps the clock used to stamp signed state expirations
// and ApproveDeviceCode / DenyDeviceCode timestamps. For tests.
func WithDeviceUIClock(now func() time.Time) DeviceUIOption {
	return func(u *DeviceUI) { u.now = now }
}

// WithInternalClientID overrides the default
// DefaultInternalDeviceUIClientID. Operators rarely change this; tests use
// it to exercise the configuration mismatch failure modes.
func WithInternalClientID(id string) DeviceUIOption {
	return func(u *DeviceUI) { u.internalClientID = id }
}

// WithDeviceUIStateNonceGenerator swaps the bounce-state nonce generator.
// For tests — production uses crypto/rand.
func WithDeviceUIStateNonceGenerator(fn func() (string, error)) DeviceUIOption {
	return func(u *DeviceUI) { u.newStateNonce = fn }
}

// WithInternalTokenURL overrides the URL the sso-callback handler POSTs to
// for code redemption. Defaults to <issuer>/token. Integration tests point
// it at their httptest server because the issuer constant cannot mirror the
// ephemeral test URL.
func WithInternalTokenURL(rawURL string) DeviceUIOption {
	return func(u *DeviceUI) { u.tokenURL = rawURL }
}

// WithDeviceUIHTTPClient swaps the http.Client used for the internal /token
// POST. The default http.DefaultClient is fine in production because the
// call is loopback; tests may inject a client with a custom transport.
func WithDeviceUIHTTPClient(c *http.Client) DeviceUIOption {
	return func(u *DeviceUI) { u.httpClient = c }
}

// NewDeviceUI constructs the device-flow verification UI handler. signingKey
// is the same OIDC__SESSION_SIGNING_KEY the SessionManager uses: the bounce
// state is HMAC-signed under it so one operator secret backs the entire
// device-flow surface. The internal tempogate-device-ui client must be
// present in clients and carry a non-empty secret; missing or public
// registrations surface as ErrInternalDeviceUIClient... here so a
// misconfigured deployment fails at construction rather than on the first
// user form-submit.
func NewDeviceUI(
	devices DeviceCodeStore,
	sessions *SessionManager,
	clients ClientRegistry,
	signingKey []byte,
	issuer string,
	opts ...DeviceUIOption,
) (*DeviceUI, error) {
	trimmedIssuer := strings.TrimRight(issuer, "/")
	u := &DeviceUI{
		devices:          devices,
		sessions:         sessions,
		clients:          clients,
		signingKey:       signingKey,
		issuer:           trimmedIssuer,
		internalClientID: DefaultInternalDeviceUIClientID,
		httpClient:       http.DefaultClient,
		now:              func() time.Time { return time.Now().UTC() },
		newStateNonce:    randomDeviceStateNonce,
	}
	for _, o := range opts {
		o(u)
	}
	if u.tokenURL == "" {
		u.tokenURL = trimmedIssuer + TokenPath
	}

	client, ok := clients[u.internalClientID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrInternalDeviceUIClientMissing, u.internalClientID)
	}
	if client.Secret == "" {
		return nil, fmt.Errorf("%w: %s", ErrInternalDeviceUIClientNotConfidential, u.internalClientID)
	}
	u.internalClientSecret = client.Secret

	pages, err := loadDevicePages()
	if err != nil {
		return nil, fmt.Errorf("oidc: load device-ui templates: %w", err)
	}
	u.pages = pages

	return u, nil
}

func loadDevicePages() (map[string]*template.Template, error) {
	out := make(map[string]*template.Template, len(devicePages))
	for name, file := range devicePages {
		t, err := template.New(name).ParseFS(deviceUITemplatesFS, "templates/base.html", "templates/"+file)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", file, err)
		}
		out[name] = t
	}
	return out, nil
}

// render produces the bytes for one of the device-ui pages. Templates are
// parsed once at construction; this is a pure CPU+memory operation that
// cannot fail under normal operation, but a regression in template data
// shape surfaces as an error here rather than a half-rendered page.
func (u *DeviceUI) render(name string, data any) ([]byte, error) {
	t, ok := u.pages[name]
	if !ok {
		return nil, fmt.Errorf("oidc: unknown device-ui page %q", name)
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "base", data); err != nil {
		return nil, fmt.Errorf("oidc: render %s: %w", name, err)
	}
	return buf.Bytes(), nil
}

func (u *DeviceUI) Register(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "device-ui-enter",
		Method:      http.MethodGet,
		Path:        DevicePath,
		Summary:     "Device-flow verification: show the user_code entry form",
		Tags:        []string{"oidc"},
	}, func(ctx context.Context, in *deviceEnterGetInput) (*htmlOutput, error) {
		return u.handleEnterGet(ctx, in)
	})

	huma.Register(api, huma.Operation{
		OperationID:   "device-ui-submit",
		Method:        http.MethodPost,
		Path:          DevicePath,
		Summary:       "Device-flow verification: accept the user_code and bounce through SSO if no session",
		Tags:          []string{"oidc"},
		DefaultStatus: http.StatusSeeOther,
	}, func(ctx context.Context, in *deviceEnterPostInput) (*deviceRedirectOrPage, error) {
		return u.handleEnterPost(ctx, in)
	})

	huma.Register(api, huma.Operation{
		OperationID:   "device-ui-sso-callback",
		Method:        http.MethodGet,
		Path:          DeviceSSOCallbackPath,
		Summary:       "Device-flow verification: SSO loopback, mint session, route to confirm",
		Tags:          []string{"oidc"},
		DefaultStatus: http.StatusSeeOther,
	}, func(ctx context.Context, in *deviceSSOCallbackInput) (*deviceRedirectOrPage, error) {
		return u.handleSSOCallback(ctx, in)
	})

	huma.Register(api, huma.Operation{
		OperationID: "device-ui-confirm",
		Method:      http.MethodGet,
		Path:        DeviceConfirmPath,
		Summary:     "Device-flow verification: render the approve/deny prompt",
		Tags:        []string{"oidc"},
	}, func(ctx context.Context, in *deviceConfirmInput) (*deviceRedirectOrPage, error) {
		return u.handleConfirm(ctx, in)
	})

	huma.Register(api, huma.Operation{
		OperationID: "device-ui-approve",
		Method:      http.MethodPost,
		Path:        DeviceApprovePath,
		Summary:     "Device-flow verification: approve the pending device authorization",
		Tags:        []string{"oidc"},
	}, func(ctx context.Context, in *deviceDecisionInput) (*htmlOutput, error) {
		return u.handleDecision(ctx, in, true)
	})

	huma.Register(api, huma.Operation{
		OperationID: "device-ui-deny",
		Method:      http.MethodPost,
		Path:        DeviceDenyPath,
		Summary:     "Device-flow verification: deny the pending device authorization",
		Tags:        []string{"oidc"},
	}, func(ctx context.Context, in *deviceDecisionInput) (*htmlOutput, error) {
		return u.handleDecision(ctx, in, false)
	})
}

// htmlOutput is the shared response shape for any device-ui page that just
// renders HTML at 200. Cache-Control: no-store keeps the user_code and email
// off intermediary caches.
type htmlOutput struct {
	ContentType  string `header:"Content-Type"`
	CacheControl string `header:"Cache-Control"`
	Body         []byte
}

// deviceRedirectOrPage is the shared response shape for handlers that may
// either redirect (303 + Location + optional Set-Cookie) or render an HTML
// error page (200 + Content-Type + Body). Huma omits empty headers, so the
// unused fields cost nothing on the wire and the two branches stay in one
// typed struct.
type deviceRedirectOrPage struct {
	Status       int
	Location     string `header:"Location"`
	SetCookie    string `header:"Set-Cookie"`
	ContentType  string `header:"Content-Type"`
	CacheControl string `header:"Cache-Control"`
	Body         []byte
}

type deviceEnterGetInput struct {
	UserCode string `query:"user_code"`
}

type deviceEnterPostInput struct {
	Cookie  string `header:"Cookie"`
	RawBody []byte `contentType:"application/x-www-form-urlencoded"`
}

type deviceSSOCallbackInput struct {
	Code  string `query:"code"`
	State string `query:"state"`
}

type deviceConfirmInput struct {
	UserCode string `query:"user_code"`
	Cookie   string `header:"Cookie"`
}

type deviceDecisionInput struct {
	Cookie  string `header:"Cookie"`
	Origin  string `header:"Origin"`
	Referer string `header:"Referer"`
	RawBody []byte `contentType:"application/x-www-form-urlencoded"`
}

// handleEnterGet renders the user_code entry form. When a verification_uri_complete
// hop pre-fills ?user_code=, the form input is seeded with the dashed
// display form so the user sees what they typed on the device.
func (u *DeviceUI) handleEnterGet(_ context.Context, in *deviceEnterGetInput) (*htmlOutput, error) {
	body, err := u.render("enter", map[string]any{
		"PostURL":           u.publicPath(DevicePath),
		"PrefilledUserCode": formatUserCode(canonicalUserCode(in.UserCode)),
	})
	if err != nil {
		return nil, fmt.Errorf("oidc: device-ui enter render: %w", err)
	}
	return u.htmlPage(body), nil
}

// handleEnterPost is the dispatcher: validate the user_code lookup, then
// either bounce through the upstream IdP (no session) or 303 straight to
// the confirm page (session present).
func (u *DeviceUI) handleEnterPost(ctx context.Context, in *deviceEnterPostInput) (*deviceRedirectOrPage, error) {
	form, err := url.ParseQuery(string(in.RawBody))
	if err != nil {
		return u.errorPage("Your submission was malformed. Please return to your device and try again."), nil
	}

	raw := form.Get("user_code")
	canonical := canonicalUserCode(raw)
	if canonical == "" {
		return u.errorPage("Enter the code shown on your device."), nil
	}

	dc, err := u.devices.LookupDeviceCodeByUserCode(ctx, canonical)
	if errors.Is(err, ErrDeviceCodeNotFound) {
		return u.errorPage("That code is not active. Check the code on your device and try again."), nil
	}
	if err != nil {
		return nil, fmt.Errorf("oidc: lookup user_code: %w", err)
	}
	if u.now().After(dc.ExpiresAt) {
		return u.errorPage("That code has expired. Restart the sign-in from your device."), nil
	}
	if dc.ApprovedAt != nil || dc.DeniedAt != nil {
		return u.errorPage("That code has already been used. Restart the sign-in from your device."), nil
	}

	req := requestFromCookieHeader(in.Cookie)
	if _, err := u.sessions.Get(ctx, req); err == nil {
		return &deviceRedirectOrPage{
			Status:   http.StatusSeeOther,
			Location: u.confirmRedirect(canonical),
		}, nil
	} else if !errors.Is(err, ErrNoSession) {
		return nil, fmt.Errorf("oidc: device-ui session lookup: %w", err)
	}

	state, err := u.signBounceState(canonical)
	if err != nil {
		return nil, fmt.Errorf("oidc: sign device-ui bounce state: %w", err)
	}
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", u.internalClientID)
	q.Set("redirect_uri", u.issuer+DeviceSSOCallbackPath)
	q.Set("scope", "openid email")
	q.Set("state", state)
	return &deviceRedirectOrPage{
		Status:   http.StatusSeeOther,
		Location: u.issuer + AuthorizePath + "?" + q.Encode(),
	}, nil
}

// handleSSOCallback verifies the bounce state, redeems the auth code at the
// internal /token endpoint to surface the authenticated email, mints the
// signed-cookie session, and 303s onward to the confirm page carrying the
// recovered user_code in the query string. The Set-Cookie travels with the
// 303 so the browser's next GET to /confirm presents the session.
func (u *DeviceUI) handleSSOCallback(ctx context.Context, in *deviceSSOCallbackInput) (*deviceRedirectOrPage, error) {
	if in.Code == "" || in.State == "" {
		return u.errorPage("That sign-in could not be completed. Restart the sign-in from your device."), nil
	}

	userCode, err := u.verifyBounceState(in.State)
	if err != nil {
		return u.errorPage("That sign-in could not be completed. Restart the sign-in from your device."), nil
	}

	email, err := u.redeemAuthCode(ctx, in.Code)
	if err != nil {
		return u.errorPage("That sign-in could not be completed. Restart the sign-in from your device."), nil
	}

	_, cookie, err := u.sessions.IssueCookie(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("oidc: device-ui session issue: %w", err)
	}

	return &deviceRedirectOrPage{
		Status:    http.StatusSeeOther,
		Location:  u.confirmRedirect(userCode),
		SetCookie: cookie.String(),
	}, nil
}

// handleConfirm renders the approve/deny prompt. A missing session sends the
// browser back to the entry form to restart the bounce; a missing or
// already-decided user_code surfaces as an error page rather than a silent
// no-op so an honest mistake still gives feedback.
func (u *DeviceUI) handleConfirm(ctx context.Context, in *deviceConfirmInput) (*deviceRedirectOrPage, error) {
	canonical := canonicalUserCode(in.UserCode)
	if canonical == "" {
		return u.errorPage("That sign-in could not be completed. Restart the sign-in from your device."), nil
	}

	req := requestFromCookieHeader(in.Cookie)
	bs, err := u.sessions.Get(ctx, req)
	if errors.Is(err, ErrNoSession) {
		return &deviceRedirectOrPage{
			Status:   http.StatusSeeOther,
			Location: u.publicPath(DevicePath) + "?user_code=" + url.QueryEscape(formatUserCode(canonical)),
		}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("oidc: device-ui confirm session lookup: %w", err)
	}

	dc, err := u.devices.LookupDeviceCodeByUserCode(ctx, canonical)
	if errors.Is(err, ErrDeviceCodeNotFound) {
		return u.errorPage("That code is not active. Restart the sign-in from your device."), nil
	}
	if err != nil {
		return nil, fmt.Errorf("oidc: device-ui confirm lookup: %w", err)
	}
	if u.now().After(dc.ExpiresAt) {
		return u.errorPage("That code has expired. Restart the sign-in from your device."), nil
	}
	if dc.ApprovedAt != nil || dc.DeniedAt != nil {
		return u.errorPage("That code has already been used. Restart the sign-in from your device."), nil
	}

	body, err := u.render("confirm", map[string]any{
		"DisplayUserCode": formatUserCode(canonical),
		"Email":           bs.Email,
		"ApproveURL":      u.publicPath(DeviceApprovePath),
		"DenyURL":         u.publicPath(DeviceDenyPath),
		"CSRFToken":       bs.SID,
	})
	if err != nil {
		return nil, fmt.Errorf("oidc: device-ui confirm render: %w", err)
	}
	return &deviceRedirectOrPage{
		Status:       http.StatusOK,
		ContentType:  "text/html; charset=utf-8",
		CacheControl: "no-store",
		Body:         body,
	}, nil
}

// handleDecision is the single funnel for the approve and deny POSTs. The
// approve boolean flips which DeviceCodeStore method runs and which HTML
// page renders on success; everything else — CSRF check, Origin check,
// already-decided handling — is shared so the two paths cannot drift.
func (u *DeviceUI) handleDecision(ctx context.Context, in *deviceDecisionInput, approve bool) (*htmlOutput, error) {
	if !u.originAllowed(in.Origin, in.Referer) {
		return u.errorHTMLPage("That request did not come from the expected page. Restart the sign-in from your device."), nil
	}

	form, err := url.ParseQuery(string(in.RawBody))
	if err != nil {
		return u.errorHTMLPage("Your submission was malformed. Please return to your device and try again."), nil
	}

	req := requestFromCookieHeader(in.Cookie)
	bs, err := u.sessions.Get(ctx, req)
	if errors.Is(err, ErrNoSession) {
		return u.errorHTMLPage("Your sign-in has expired. Restart the sign-in from your device."), nil
	}
	if err != nil {
		return nil, fmt.Errorf("oidc: device-ui decision session lookup: %w", err)
	}

	presented := form.Get("csrf_token")
	if subtle.ConstantTimeCompare([]byte(presented), []byte(bs.SID)) != 1 {
		return u.errorHTMLPage("That submission could not be verified. Restart the sign-in from your device."), nil
	}

	canonical := canonicalUserCode(form.Get("user_code"))
	if canonical == "" {
		return u.errorHTMLPage("That submission was missing the device code. Restart the sign-in from your device."), nil
	}

	now := u.now()
	if approve {
		err = u.devices.ApproveDeviceCode(ctx, canonical, bs.Email, now)
	} else {
		err = u.devices.DenyDeviceCode(ctx, canonical, now)
	}
	if errors.Is(err, ErrDeviceCodeNotPending) {
		return u.errorHTMLPage("That code has already been used. Restart the sign-in from your device."), nil
	}
	if errors.Is(err, ErrDeviceCodeNotFound) {
		return u.errorHTMLPage("That code is not active. Restart the sign-in from your device."), nil
	}
	if err != nil {
		return nil, fmt.Errorf("oidc: device-ui decision flip: %w", err)
	}

	page := "approved"
	if !approve {
		page = "denied"
	}
	body, err := u.render(page, nil)
	if err != nil {
		return nil, fmt.Errorf("oidc: device-ui %s render: %w", page, err)
	}
	return u.htmlPage(body), nil
}

// redeemAuthCode posts the loopback /token call that turns the auth code
// the upstream callback minted into an access/id token, then decodes the
// id_token's email claim. The token was just signed by tempogate itself
// inside this same process, so the payload is authoritative without a
// signature re-check here — the cost of pulling in keys.Verifier just to
// reverify our own freshly minted token isn't paid back by the threat
// model.
func (u *DeviceUI) redeemAuthCode(ctx context.Context, code string) (string, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", u.issuer+DeviceSSOCallbackPath)
	form.Set("client_id", u.internalClientID)
	form.Set("client_secret", u.internalClientSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("oidc: build internal /token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("oidc: internal /token round-trip: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return "", fmt.Errorf("oidc: internal /token status %d", resp.StatusCode)
	}

	var body struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("oidc: decode internal /token response: %w", err)
	}
	if body.IDToken == "" {
		return "", errors.New("oidc: internal /token returned no id_token")
	}

	parts := strings.SplitN(body.IDToken, ".", 3)
	if len(parts) != 3 {
		return "", errors.New("oidc: malformed id_token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("oidc: decode id_token payload: %w", err)
	}
	var claims struct {
		Email string `json:"email"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("oidc: parse id_token claims: %w", err)
	}
	if claims.Email == "" {
		return "", errors.New("oidc: id_token has no email claim")
	}
	return claims.Email, nil
}

// signBounceState wraps a canonical user_code into the HMAC-signed,
// short-TTL `state` parameter the upstream /authorize redirect carries. It
// is the only state device-ui keeps across the IdP bounce: the user_code is
// recovered verbatim on the other side, and the exp + nonce together rule
// out replay.
func (u *DeviceUI) signBounceState(canonicalUserCode string) (string, error) {
	nonce, err := u.newStateNonce()
	if err != nil {
		return "", err
	}
	payload := deviceBounceState{
		UserCode: canonicalUserCode,
		Nonce:    nonce,
		Exp:      u.now().Add(deviceStateTTL).Unix(),
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, u.signingKey)
	mac.Write(raw)
	return base64.RawURLEncoding.EncodeToString(raw) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (u *DeviceUI) verifyBounceState(signed string) (string, error) {
	parts := strings.SplitN(signed, ".", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", errors.New("malformed state")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", err
	}
	gotMAC, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}
	want := hmac.New(sha256.New, u.signingKey)
	want.Write(raw)
	if subtle.ConstantTimeCompare(gotMAC, want.Sum(nil)) != 1 {
		return "", errors.New("bad state mac")
	}
	var payload deviceBounceState
	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", err
	}
	if u.now().Unix() > payload.Exp {
		return "", errors.New("state expired")
	}
	if canonicalUserCode(payload.UserCode) == "" {
		return "", errors.New("state has no user_code")
	}
	return canonicalUserCode(payload.UserCode), nil
}

type deviceBounceState struct {
	UserCode string `json:"user_code"`
	Nonce    string `json:"nonce"`
	Exp      int64  `json:"exp"`
}

// originAllowed enforces the same-origin rule for Approve / Deny POSTs:
// Origin, if present, must equal the issuer's scheme+host; otherwise the
// Referer must start with the issuer. Either of those is sufficient — a
// modern browser always sends one of the two on a same-origin POST, so the
// pair forms a defence-in-depth check on top of SameSite=Lax.
func (u *DeviceUI) originAllowed(origin, referer string) bool {
	expected, ok := originPrefix(u.issuer)
	if !ok {
		return false
	}
	if origin != "" {
		return origin == expected
	}
	return referer != "" && strings.HasPrefix(referer, expected)
}

func originPrefix(issuer string) (string, bool) {
	parsed, err := url.Parse(issuer)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", false
	}
	return parsed.Scheme + "://" + parsed.Host, true
}

func (u *DeviceUI) confirmRedirect(canonical string) string {
	return u.publicPath(DeviceConfirmPath) + "?user_code=" + url.QueryEscape(formatUserCode(canonical))
}

// publicPath returns the URL path the browser sees for a route registered
// at p. When the api package mounts the OIDC surface under a base path, the
// huma adapter prepends that prefix to the registered Path; the issuer
// already encodes it, so we reuse the issuer's path component here so form
// actions and Location headers resolve to the exact mount the live routes
// listen on.
func (u *DeviceUI) publicPath(p string) string {
	parsed, err := url.Parse(u.issuer)
	if err != nil {
		return p
	}
	prefix := strings.TrimRight(parsed.Path, "/")
	return prefix + p
}

func (u *DeviceUI) htmlPage(body []byte) *htmlOutput {
	return &htmlOutput{
		ContentType:  "text/html; charset=utf-8",
		CacheControl: "no-store",
		Body:         body,
	}
}

func (u *DeviceUI) errorPage(reason string) *deviceRedirectOrPage {
	body, err := u.render("error", map[string]any{"Reason": reason})
	if err != nil {
		body = []byte("device verification error")
	}
	return &deviceRedirectOrPage{
		Status:       http.StatusOK,
		ContentType:  "text/html; charset=utf-8",
		CacheControl: "no-store",
		Body:         body,
	}
}

func (u *DeviceUI) errorHTMLPage(reason string) *htmlOutput {
	body, err := u.render("error", map[string]any{"Reason": reason})
	if err != nil {
		body = []byte("device verification error")
	}
	return u.htmlPage(body)
}

// requestFromCookieHeader builds the minimal http.Request a SessionManager
// needs to read its cookie. Huma exposes the raw Cookie header value as a
// string; rather than reimplement cookie parsing here, we feed it back into
// the stdlib via a synthetic request.
func requestFromCookieHeader(cookieHeader string) *http.Request {
	r := &http.Request{Header: http.Header{}}
	if cookieHeader != "" {
		r.Header.Set("Cookie", cookieHeader)
	}
	return r
}

// canonicalUserCode normalises a user-typed code to the upper-case,
// no-dashes form the store indexes on. Whitespace is also stripped so a
// paste from the device that picked up a stray space is still accepted.
func canonicalUserCode(raw string) string {
	var b strings.Builder
	b.Grow(len(raw))
	for _, r := range raw {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r - 32)
		case (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
		case r == '-' || r == ' ' || r == '\t':
			// strip
		default:
			// strip — keeps the lookup faithful to what the device shows
		}
	}
	return b.String()
}

func randomDeviceStateNonce() (string, error) {
	b := make([]byte, deviceStateNonceBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
