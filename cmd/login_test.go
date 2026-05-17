package cmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"

	"github.com/fenmoai/tempogate/cli"
)

type LoginCmdSuite struct {
	suite.Suite

	origRunner func(context.Context, ...cli.Option) (cli.Token, error)
}

func TestLoginCmdSuite(t *testing.T) {
	suite.Run(t, new(LoginCmdSuite))
}

func (s *LoginCmdSuite) SetupTest() {
	s.origRunner = loginRunner
}

func (s *LoginCmdSuite) TearDownTest() {
	loginRunner = s.origRunner
}

func (s *LoginCmdSuite) TestDefaultRunnerDelegatesToFlow() {
	// Exercise the production seam (not the test stub): an empty issuer must
	// fail fast in cli.Flow without opening a browser or hitting the network.
	_, err := loginRunner(context.Background(), cli.WithIssuer(""))
	s.Require().Error(err)
	s.Contains(err.Error(), "issuer is required")
}

func (s *LoginCmdSuite) TestRequiresIssuer() {
	s.T().Setenv("TEMPOGATE__ISSUER", "")

	cmd := newLoginCmd(RunParams{Logger: zap.NewNop()})
	cmd.SetOut(new(testWriter))
	cmd.SetErr(new(testWriter))

	err := cmd.ExecuteContext(context.Background())
	s.Require().Error(err)
	s.Contains(err.Error(), "issuer is required")
	s.Contains(err.Error(), "TEMPOGATE__ISSUER")
}

func (s *LoginCmdSuite) TestEnvIssuerPrintsTokenAndPersists() {
	s.T().Setenv("TEMPOGATE__ISSUER", "https://tempogate.example.com")
	expiry := time.Date(2031, 1, 2, 3, 4, 5, 0, time.UTC)
	loginRunner = func(_ context.Context, _ ...cli.Option) (cli.Token, error) {
		return cli.Token{AccessToken: "header.payload.sig", RefreshToken: "r-1", ExpiresAt: expiry}, nil
	}
	path := filepath.Join(s.T().TempDir(), "nested", "token.json")

	var out, errOut bytes.Buffer
	cmd := newLoginCmd(RunParams{Logger: zap.NewNop()})
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs([]string{"--token-file", path})

	s.Require().NoError(cmd.ExecuteContext(context.Background()))
	s.Equal("header.payload.sig\n", out.String(), "stdout carries only the token")
	s.Contains(errOut.String(), "Signed in. Token saved to "+path)
	s.Contains(errOut.String(), "valid until 2031-01-02T03:04:05Z")

	persisted, err := cli.Load(path)
	s.Require().NoError(err)
	s.Equal("header.payload.sig", persisted.AccessToken)
	s.Equal("r-1", persisted.RefreshToken)
}

func (s *LoginCmdSuite) TestTokenPersistenceFailurePropagates() {
	s.T().Setenv("TEMPOGATE__ISSUER", "https://tempogate.example.com")
	loginRunner = func(_ context.Context, _ ...cli.Option) (cli.Token, error) {
		return cli.Token{AccessToken: "t", RefreshToken: "r"}, nil
	}
	notADir := filepath.Join(s.T().TempDir(), "afile")
	s.Require().NoError(os.WriteFile(notADir, []byte("x"), 0o600))

	cmd := newLoginCmd(RunParams{Logger: zap.NewNop()})
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(new(testWriter))
	cmd.SetArgs([]string{"--token-file", filepath.Join(notADir, "token.json")})

	err := cmd.ExecuteContext(context.Background())
	s.Require().Error(err)
	s.Contains(err.Error(), "create token dir")
	s.Empty(out.String(), "the token must not be printed if it could not be persisted")
}

func (s *LoginCmdSuite) TestTokenPathResolutionFailurePropagates() {
	s.T().Setenv("TEMPOGATE__ISSUER", "https://tempogate.example.com")
	s.T().Setenv("HOME", "")
	s.T().Setenv("USERPROFILE", "")

	cmd := newLoginCmd(RunParams{Logger: zap.NewNop()})
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetOut(new(testWriter))
	cmd.SetErr(new(testWriter))
	cmd.SetArgs([]string{}) // no --token-file ⇒ must resolve the default

	err := cmd.ExecuteContext(context.Background())
	s.Require().Error(err)
	s.Contains(err.Error(), "home directory")
}

func (s *LoginCmdSuite) TestFlagIssuerOverridesEnvAndErrorsPropagate() {
	s.T().Setenv("TEMPOGATE__ISSUER", "https://from-env.example.com")
	loginRunner = func(_ context.Context, _ ...cli.Option) (cli.Token, error) {
		return cli.Token{}, errors.New("cli: token exchange rejected (invalid_grant): nope")
	}

	var out, errOut bytes.Buffer
	cmd := newLoginCmd(RunParams{Logger: zap.NewNop()})
	// Mirror production, where login runs under NewRootCmd (SilenceUsage/
	// SilenceErrors), so an error does not spray usage onto stdout.
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs([]string{"--issuer", "https://from-flag.example.com"})

	err := cmd.ExecuteContext(context.Background())
	s.Require().Error(err)
	s.Contains(err.Error(), "invalid_grant")
	s.Empty(out.String(), "no token is printed on failure")
}
