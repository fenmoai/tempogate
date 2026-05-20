package admin_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/google/uuid"
	"github.com/stretchr/testify/suite"

	"github.com/fenmoai/tempogate/admin"
	"github.com/fenmoai/tempogate/keys"
)

const testIssuer = "https://tempogate.test"

var signNow = time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)

// memKeyStore satisfies keys.KeyStore for the test Signer. Mirrors the shape
// of the same-named helper in oidc/token_test.go; redefined here because Go's
// _test.go scoping does not export across packages.
type memKeyStore struct {
	mu  sync.Mutex
	kps []keys.Keypair
}

func (m *memKeyStore) SaveKeypair(_ context.Context, kp keys.Keypair) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.kps = append(m.kps, kp)
	return nil
}

func (m *memKeyStore) LoadKeypairs(_ context.Context) ([]keys.Keypair, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]keys.Keypair, len(m.kps))
	copy(out, m.kps)
	return out, nil
}

// memRegistry is an in-memory admin.KeyRegistry. Inserts preserve insertion
// order; List returns rows in id-DESC order (mirrors the sqlite behaviour the
// real handler depends on). MarkIntegrationKeyRevoked is idempotent.
type memRegistry struct {
	mu   sync.Mutex
	rows map[string]admin.IntegrationKey
	now  func() time.Time
}

func newMemRegistry(now func() time.Time) *memRegistry {
	return &memRegistry{rows: map[string]admin.IntegrationKey{}, now: now}
}

func (m *memRegistry) Save(_ context.Context, k admin.IntegrationKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rows[k.ID] = k
	return nil
}

func (m *memRegistry) ByID(_ context.Context, id string) (admin.IntegrationKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	row, ok := m.rows[id]
	if !ok {
		return admin.IntegrationKey{}, fmt.Errorf("%w: %s", admin.ErrIntegrationKeyNotFound, id)
	}
	return row, nil
}

func (m *memRegistry) List(_ context.Context, f admin.ListFilter) ([]admin.IntegrationKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]admin.IntegrationKey, 0, len(m.rows))
	for _, k := range m.rows {
		if f.Owner != "" && k.Owner != f.Owner {
			continue
		}
		if f.Namespace != "" && k.Namespace != f.Namespace {
			continue
		}
		if f.Cursor != "" && k.ID >= f.Cursor {
			continue
		}
		out = append(out, k)
	}
	// id DESC
	for i := 0; i < len(out)-1; i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j].ID > out[i].ID {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	if f.Limit > 0 && len(out) > f.Limit+1 {
		out = out[:f.Limit+1]
	}
	return out, nil
}

func (m *memRegistry) MarkRevoked(_ context.Context, id string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	row, ok := m.rows[id]
	if !ok {
		return "", fmt.Errorf("%w: %s", admin.ErrIntegrationKeyNotFound, id)
	}
	if row.RevokedAt == nil {
		t := m.now()
		row.RevokedAt = &t
		m.rows[id] = row
	}
	return row.JTI, nil
}

type KeysSuite struct {
	suite.Suite

	ctx      context.Context
	registry *memRegistry
	keys     *keys.Keys
	signer   *keys.Signer
	verifier *keys.Verifier
	srv      *httptest.Server
	client   *http.Client

	idTicker int
	now      time.Time
}

func TestKeysSuite(t *testing.T) {
	suite.Run(t, new(KeysSuite))
}

func (s *KeysSuite) SetupTest() {
	s.ctx = context.Background()
	s.now = signNow
	s.idTicker = 0

	ks := &memKeyStore{}
	s.keys = keys.New(keys.WithStore(ks), keys.WithGenerateOptions(keys.WithRSABits(2048)))
	s.Require().NoError(s.keys.Init(s.ctx))

	s.signer = keys.NewSigner(
		keys.WithKeys(s.keys),
		keys.WithIssuer(testIssuer),
		keys.WithTokenClock(s.clock()),
	)
	s.verifier = keys.NewVerifier(
		keys.WithKeys(s.keys),
		keys.WithIssuer(testIssuer),
		keys.WithTokenClock(func() time.Time { return s.now.Add(time.Second) }),
	)
	s.registry = newMemRegistry(s.clock())

	h := admin.NewKeys(s.registry, s.signer,
		admin.WithClock(s.clock()),
		admin.WithIDGenerator(s.nextID),
	)

	mux := http.NewServeMux()
	h.Register(humago.New(mux, huma.DefaultConfig("test", "0.0.0")))
	s.srv = httptest.NewServer(mux)
	s.client = &http.Client{}
}

func (s *KeysSuite) TearDownTest() {
	s.srv.Close()
}

func (s *KeysSuite) clock() func() time.Time {
	return func() time.Time { return s.now }
}

// nextID returns a UUIDv7-shaped id whose lexicographic order matches the
// suite's call sequence, so list-order assertions stay deterministic.
func (s *KeysSuite) nextID() (string, error) {
	s.idTicker++
	// UUIDv7-shape but driven by a counter so two consecutive calls have a
	// stable strict total order. The real handler uses uuid.NewV7().
	return fmt.Sprintf("00000000-0000-7000-8000-%012d", s.idTicker), nil
}

type postBody struct {
	Namespace string  `json:"namespace"`
	Role      string  `json:"role"`
	Owner     string  `json:"owner"`
	ExpiresAt *string `json:"expires_at,omitempty"`
}

type postResp struct {
	ID        string  `json:"id"`
	JWT       string  `json:"jwt"`
	ExpiresAt *string `json:"expires_at,omitempty"`
}

type keyResp struct {
	ID        string  `json:"id"`
	Namespace string  `json:"namespace"`
	Role      string  `json:"role"`
	Owner     string  `json:"owner"`
	CreatedAt string  `json:"created_at"`
	ExpiresAt *string `json:"expires_at,omitempty"`
	RevokedAt *string `json:"revoked_at,omitempty"`
}

type listResp struct {
	Items      []keyResp `json:"items"`
	NextCursor string    `json:"next_cursor"`
}

func (s *KeysSuite) postKey(body postBody) (*http.Response, []byte) {
	raw, err := json.Marshal(body)
	s.Require().NoError(err)
	resp, err := s.client.Post(s.srv.URL+"/admin/keys", "application/json", strings.NewReader(string(raw)))
	s.Require().NoError(err)
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)
	return resp, b
}

func (s *KeysSuite) getKey(id string) (*http.Response, []byte) {
	resp, err := s.client.Get(s.srv.URL + "/admin/keys/" + id)
	s.Require().NoError(err)
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)
	return resp, b
}

func (s *KeysSuite) listKeys(q string) (*http.Response, []byte) {
	u := s.srv.URL + "/admin/keys"
	if q != "" {
		u += "?" + q
	}
	resp, err := s.client.Get(u)
	s.Require().NoError(err)
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)
	return resp, b
}

func (s *KeysSuite) deleteKey(id string) *http.Response {
	req, err := http.NewRequest(http.MethodDelete, s.srv.URL+"/admin/keys/"+id, http.NoBody)
	s.Require().NoError(err)
	resp, err := s.client.Do(req)
	s.Require().NoError(err)
	defer func() { _ = resp.Body.Close() }()
	return resp
}

func (s *KeysSuite) TestPostMintsKeyReturns201() {
	resp, raw := s.postKey(postBody{Namespace: "payments", Role: "worker", Owner: "svc-recon"})
	s.Require().Equal(http.StatusCreated, resp.StatusCode, "body=%s", string(raw))

	var got postResp
	s.Require().NoError(json.Unmarshal(raw, &got))

	s.NotEmpty(got.ID)
	s.NotEmpty(got.JWT)
	s.Nil(got.ExpiresAt, "expires_at omitted when input nil")

	// Persisted row matches the response.
	row, err := s.registry.ByID(s.ctx, got.ID)
	s.Require().NoError(err)
	s.Equal("payments", row.Namespace)
	s.Equal(admin.RoleWorker, row.Role)
	s.Equal("svc-recon", row.Owner)
	s.NotEmpty(row.JTI)

	// JWT carries the persisted JTI and the per-key permission.
	tok, err := s.verifier.Verify(s.ctx, got.JWT)
	s.Require().NoError(err)
	jti, ok := tok.JwtID()
	s.Require().True(ok)
	s.Equal(row.JTI, jti)
	sub, ok := tok.Subject()
	s.Require().True(ok)
	s.Equal("svc-recon", sub)

	perms, ok := tok.Field("permissions")
	s.Require().True(ok)
	asSlice, ok := perms.([]any)
	s.Require().True(ok)
	s.Require().Len(asSlice, 1)
	s.Equal("payments:worker", asSlice[0])
}

func (s *KeysSuite) TestPostWithExpiresAtStampsExpClaim() {
	exp := s.now.Add(2 * time.Hour)
	body := postBody{
		Namespace: "ns",
		Role:      "read",
		Owner:     "o",
		ExpiresAt: ptr(exp.Format(time.RFC3339)),
	}
	resp, raw := s.postKey(body)
	s.Require().Equal(http.StatusCreated, resp.StatusCode, "body=%s", string(raw))

	var got postResp
	s.Require().NoError(json.Unmarshal(raw, &got))
	s.Require().NotNil(got.ExpiresAt)

	tok, err := s.verifier.Verify(s.ctx, got.JWT)
	s.Require().NoError(err)
	gotExp, ok := tok.Expiration()
	s.Require().True(ok)
	s.True(gotExp.Equal(exp), "exp claim must equal requested expires_at; got %s want %s", gotExp, exp)
}

func (s *KeysSuite) TestPostValidatesRole() {
	cases := []struct {
		name string
		role string
		want int
	}{
		{"read", "read", http.StatusCreated},
		{"write", "write", http.StatusCreated},
		{"worker", "worker", http.StatusCreated},
		{"admin", "admin", http.StatusCreated},
		{"empty role", "", http.StatusBadRequest},
		{"unknown role", "superuser", http.StatusBadRequest},
		{"wrong case", "Read", http.StatusBadRequest},
	}
	for _, tc := range cases {
		s.Run(tc.name, func() {
			resp, raw := s.postKey(postBody{Namespace: "ns", Role: tc.role, Owner: "o"})
			s.Equal(tc.want, resp.StatusCode, "body=%s", string(raw))
		})
	}
}

func (s *KeysSuite) TestPostRejectsEmptyNamespaceOrOwner() {
	cases := []struct {
		name string
		body postBody
	}{
		{"empty namespace", postBody{Namespace: "", Role: "read", Owner: "o"}},
		{"empty owner", postBody{Namespace: "ns", Role: "read", Owner: ""}},
	}
	for _, tc := range cases {
		s.Run(tc.name, func() {
			resp, _ := s.postKey(tc.body)
			s.Equal(http.StatusBadRequest, resp.StatusCode)
		})
	}
}

func (s *KeysSuite) TestGetByIDReturnsMetadataWithoutJWT() {
	resp, raw := s.postKey(postBody{Namespace: "ns", Role: "read", Owner: "o"})
	s.Require().Equal(http.StatusCreated, resp.StatusCode)
	var posted postResp
	s.Require().NoError(json.Unmarshal(raw, &posted))

	getResp, getBody := s.getKey(posted.ID)
	s.Require().Equal(http.StatusOK, getResp.StatusCode, "body=%s", string(getBody))
	s.NotContains(string(getBody), posted.JWT, "GET must not re-emit the JWT")

	var got keyResp
	s.Require().NoError(json.Unmarshal(getBody, &got))
	s.Equal(posted.ID, got.ID)
	s.Equal("ns", got.Namespace)
	s.Equal("read", got.Role)
	s.Equal("o", got.Owner)
	s.Nil(got.RevokedAt)
}

func (s *KeysSuite) TestGetByIDUnknownReturns404() {
	resp, _ := s.getKey(uuid.NewString())
	s.Equal(http.StatusNotFound, resp.StatusCode)
}

func (s *KeysSuite) TestListFiltersAndPaginates() {
	mk := func(ns, owner string) string {
		resp, raw := s.postKey(postBody{Namespace: ns, Role: "read", Owner: owner})
		s.Require().Equal(http.StatusCreated, resp.StatusCode)
		var p postResp
		s.Require().NoError(json.Unmarshal(raw, &p))
		return p.ID
	}
	a := mk("ns-1", "alice")
	b := mk("ns-1", "bob")
	c := mk("ns-2", "alice")
	d := mk("ns-1", "alice")
	e := mk("ns-1", "alice")

	// Filter by owner=alice → a, c, d, e. Order is id-DESC.
	resp, raw := s.listKeys("owner=alice&limit=10")
	s.Require().Equal(http.StatusOK, resp.StatusCode, "body=%s", string(raw))
	var lst listResp
	s.Require().NoError(json.Unmarshal(raw, &lst))
	s.Empty(lst.NextCursor)
	s.Require().Len(lst.Items, 4)
	s.Equal(e, lst.Items[0].ID)
	s.Equal(d, lst.Items[1].ID)
	s.Equal(c, lst.Items[2].ID)
	s.Equal(a, lst.Items[3].ID)

	// Filter by namespace=ns-1 → a, b, d, e
	resp, raw = s.listKeys("namespace=ns-1&limit=10")
	s.Require().Equal(http.StatusOK, resp.StatusCode)
	s.Require().NoError(json.Unmarshal(raw, &lst))
	ids := []string{lst.Items[0].ID, lst.Items[1].ID, lst.Items[2].ID, lst.Items[3].ID}
	s.Contains(ids, a)
	s.Contains(ids, b)
	s.Contains(ids, d)
	s.Contains(ids, e)
	s.NotContains(ids, c)

	// Paginate owner=alice with limit=2 → e,d then c,a
	resp, raw = s.listKeys("owner=alice&limit=2")
	s.Require().Equal(http.StatusOK, resp.StatusCode)
	s.Require().NoError(json.Unmarshal(raw, &lst))
	s.Require().Len(lst.Items, 2)
	s.Equal(e, lst.Items[0].ID)
	s.Equal(d, lst.Items[1].ID)
	s.NotEmpty(lst.NextCursor, "more results available → nextCursor must be set")

	resp, raw = s.listKeys("owner=alice&limit=2&cursor=" + lst.NextCursor)
	s.Require().Equal(http.StatusOK, resp.StatusCode)
	s.Require().NoError(json.Unmarshal(raw, &lst))
	s.Require().Len(lst.Items, 2)
	s.Equal(c, lst.Items[0].ID)
	s.Equal(a, lst.Items[1].ID)
	s.Empty(lst.NextCursor, "last page → nextCursor must be empty")
}

func (s *KeysSuite) TestListRejectsMalformedCursor() {
	resp, _ := s.listKeys("cursor=not-a-uuid")
	s.Equal(http.StatusBadRequest, resp.StatusCode)
}

func (s *KeysSuite) TestDeleteIdempotent() {
	resp, raw := s.postKey(postBody{Namespace: "ns", Role: "read", Owner: "o"})
	s.Require().Equal(http.StatusCreated, resp.StatusCode)
	var posted postResp
	s.Require().NoError(json.Unmarshal(raw, &posted))

	// First delete revokes.
	del := s.deleteKey(posted.ID)
	s.Equal(http.StatusNoContent, del.StatusCode)

	// GET shows revokedAt.
	getResp, getBody := s.getKey(posted.ID)
	s.Require().Equal(http.StatusOK, getResp.StatusCode)
	var got keyResp
	s.Require().NoError(json.Unmarshal(getBody, &got))
	s.Require().NotNil(got.RevokedAt)

	// Second delete is idempotent.
	del2 := s.deleteKey(posted.ID)
	s.Equal(http.StatusNoContent, del2.StatusCode)
}

func (s *KeysSuite) TestDeleteUnknownReturns404() {
	resp := s.deleteKey(uuid.NewString())
	s.Equal(http.StatusNotFound, resp.StatusCode)
}

func (s *KeysSuite) TestPathConstantsMatchRegisteredRoutes() {
	s.Equal("/admin/keys", admin.KeysPath)
	s.Equal("/admin/keys/{id}", admin.KeysIDPath)
}

func (s *KeysSuite) TestStoreErrorBubblesUp() {
	// Sanity: an unexpected (non-NotFound) error from the registry surfaces
	// as 500 rather than being silently swallowed.
	failing := &failingRegistry{wrapped: s.registry, byIDErr: errors.New("disk on fire")}
	h := admin.NewKeys(failing, s.signer,
		admin.WithClock(s.clock()),
		admin.WithIDGenerator(s.nextID),
	)
	mux := http.NewServeMux()
	h.Register(humago.New(mux, huma.DefaultConfig("test", "0.0.0")))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/admin/keys/" + uuid.NewString())
	s.Require().NoError(err)
	defer func() { _ = resp.Body.Close() }()
	s.Equal(http.StatusInternalServerError, resp.StatusCode)
}

type failingRegistry struct {
	wrapped admin.KeyRegistry
	byIDErr error
}

func (f *failingRegistry) Save(ctx context.Context, k admin.IntegrationKey) error {
	return f.wrapped.Save(ctx, k)
}
func (f *failingRegistry) ByID(_ context.Context, _ string) (admin.IntegrationKey, error) {
	return admin.IntegrationKey{}, f.byIDErr
}
func (f *failingRegistry) List(ctx context.Context, q admin.ListFilter) ([]admin.IntegrationKey, error) {
	return f.wrapped.List(ctx, q)
}
func (f *failingRegistry) MarkRevoked(ctx context.Context, id string) (string, error) {
	return f.wrapped.MarkRevoked(ctx, id)
}

func ptr[T any](v T) *T { return &v }
