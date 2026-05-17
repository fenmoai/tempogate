package cmd

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"

	"github.com/fenmoai/tempogate/cli"
)

type LoginCmdSuite struct {
	suite.Suite

	origRunner func(context.Context, ...cli.Option) (string, time.Time, error)
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

func (s *LoginCmdSuite) TestEnvIssuerPrintsTokenToStdout() {
	s.T().Setenv("TEMPOGATE__ISSUER", "https://tempogate.example.com")
	expiry := time.Date(2031, 1, 2, 3, 4, 5, 0, time.UTC)
	loginRunner = func(_ context.Context, _ ...cli.Option) (string, time.Time, error) {
		return "header.payload.sig", expiry, nil
	}

	var out, errOut bytes.Buffer
	cmd := newLoginCmd(RunParams{Logger: zap.NewNop()})
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs([]string{})

	s.Require().NoError(cmd.ExecuteContext(context.Background()))
	s.Equal("header.payload.sig\n", out.String(), "stdout carries only the token")
	s.Contains(errOut.String(), "Signed in. Token valid until 2031-01-02T03:04:05Z")
}

func (s *LoginCmdSuite) TestFlagIssuerOverridesEnvAndErrorsPropagate() {
	s.T().Setenv("TEMPOGATE__ISSUER", "https://from-env.example.com")
	loginRunner = func(_ context.Context, _ ...cli.Option) (string, time.Time, error) {
		return "", time.Time{}, errors.New("cli: token exchange rejected (invalid_grant): nope")
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
