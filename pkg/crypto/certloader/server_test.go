// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package certloader

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"go.uber.org/goleak"
)

func TestNewWatchedServerConfigErrors(t *testing.T) {
	dir, hubble, relay := directories(t)
	setup(t, hubble, relay)
	defer cleanup(dir)
	logger := hivetest.Logger(t)

	_, err := NewWatchedServerConfig(logger, relay.caFiles, "", hubble.privkeyFile)
	assert.Equal(t, ErrMissingCertFile, err)

	_, err = NewWatchedServerConfig(logger, relay.caFiles, hubble.certFile, "")
	assert.Equal(t, ErrMissingPrivkeyFile, err)
}

func TestWatchedServerConfigIsMutualTLS(t *testing.T) {
	t.Cleanup(func() {
		goleak.VerifyNone(t)
	})

	dir, hubble, relay := directories(t)
	setup(t, hubble, relay)
	defer cleanup(dir)
	logger := hivetest.Logger(t)

	tests := []struct {
		name        string
		constructor func() (*WatchedServerConfig, error)
		isMutualTLS bool
	}{
		{
			name: "keypair only",
			constructor: func() (*WatchedServerConfig, error) {
				return NewWatchedServerConfig(logger, nil, hubble.certFile, hubble.privkeyFile)
			},
			isMutualTLS: false,
		},
		{
			name: "CA and keypair",
			constructor: func() (*WatchedServerConfig, error) {
				return NewWatchedServerConfig(logger, relay.caFiles, hubble.certFile, hubble.privkeyFile)
			},
			isMutualTLS: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := tt.constructor()
			if err != nil {
				t.Error(err)
				return
			}
			defer s.Stop()
			if tt.isMutualTLS {
				assert.True(t, s.IsMutualTLS())
			} else {
				assert.False(t, s.IsMutualTLS())
			}
		})
	}
}

func TestFutureWatchedServerConfig(t *testing.T) {
	t.Cleanup(func() {
		goleak.VerifyNone(t)
	})

	dir, hubble, relay := directories(t)
	// don't call setup() yet, we only want the directories created without the
	// TLS files.
	defer cleanup(dir)
	logger := hivetest.Logger(t)

	ch, err := FutureWatchedServerConfig(t.Context(), logger, relay.caFiles, hubble.certFile, hubble.privkeyFile)
	assert.NoError(t, err)

	// the files don't exists, expect the config to not be ready yet.
	select {
	case <-ch:
		t.Fatal("FutureWatchedServerConfig should not be ready without the TLS files")
	case <-time.After(testReloadDelay):
	}

	setup(t, hubble, relay)

	// the files exists now, expect the watcher to become ready.
	s := <-ch
	if assert.NotNil(t, s) {
		s.Stop()
	}
}

func TestNewWatchedServerConfig(t *testing.T) {
	t.Cleanup(func() {
		goleak.VerifyNone(t)
	})

	dir, hubble, relay := directories(t)
	setup(t, hubble, relay)
	defer cleanup(dir)
	logger := hivetest.Logger(t)

	expectedCaCertPool := x509.NewCertPool()
	if ok := expectedCaCertPool.AppendCertsFromPEM(initialRelayClientCA); !ok {
		t.Fatal("AppendCertsFromPEM", initialRelayClientCA)
	}
	expectedKeypair, err := tls.X509KeyPair(initialHubbleServerCertificate, initialHubbleServerPrivkey)
	if err != nil {
		t.Fatal("tls.X509KeyPair", err)
	}

	s, err := NewWatchedServerConfig(logger, relay.caFiles, hubble.certFile, hubble.privkeyFile)
	assert.NoError(t, err)
	assert.NotNil(t, s)
	defer s.Stop()

	generator := s.ServerConfig(&tls.Config{
		MinVersion: tls.VersionTLS13,
	})
	assert.NotNil(t, generator)
	tlsConfig, err := generator.GetConfigForClient(nil)
	assert.NoError(t, err)
	assert.NotNil(t, tlsConfig)
	assert.Equal(t, []tls.Certificate{expectedKeypair}, tlsConfig.Certificates)
	assert.Equal(t, expectedCaCertPool.Subjects(), tlsConfig.ClientCAs.Subjects())
	assert.Equal(t, tls.RequireAndVerifyClientCert, tlsConfig.ClientAuth)
	// Check that our base option is honored.
	assert.Equal(t, uint16(tls.VersionTLS13), tlsConfig.MinVersion)
	// check that the ALPN protocol is set.
	assert.Contains(t, tlsConfig.NextProtos, alpnProtocolH2)
}

func TestWatchedServerConfigRotation(t *testing.T) {
	t.Cleanup(func() {
		goleak.VerifyNone(t)
	})

	dir, hubble, relay := directories(t)
	setup(t, hubble, relay)
	defer cleanup(dir)
	logger := hivetest.Logger(t)

	expectedCaCertPool := x509.NewCertPool()
	if ok := expectedCaCertPool.AppendCertsFromPEM(rotatedRelayClientCA); !ok {
		t.Fatal("AppendCertsFromPEM", rotatedRelayClientCA)
	}
	expectedKeypair, err := tls.X509KeyPair(rotatedHubbleServerCertificate, rotatedHubbleServerPrivkey)
	if err != nil {
		t.Fatal("tls.X509KeyPair", err)
	}

	s, err := NewWatchedServerConfig(logger, relay.caFiles, hubble.certFile, hubble.privkeyFile)
	assert.NoError(t, err)
	assert.NotNil(t, s)
	defer s.Stop()

	prevKeypairGeneration, prevCaCertPoolGeneration := s.generations()
	rotate(t, hubble, relay)

	// wait until both keypair and caCertPool have been reloaded
	ticker := time.NewTicker(testReloadDelay)
	defer ticker.Stop()
	for range ticker.C {
		keypairGeneration, caCertPoolGeneration := s.generations()
		keypairUpdated := keypairGeneration > prevKeypairGeneration
		caCertPoolUpdated := caCertPoolGeneration > prevCaCertPoolGeneration
		if keypairUpdated && caCertPoolUpdated {
			break
		}
	}

	generator := s.ServerConfig(&tls.Config{
		MinVersion: tls.VersionTLS13,
	})
	assert.NotNil(t, generator)
	tlsConfig, err := generator.GetConfigForClient(nil)
	assert.NoError(t, err)
	assert.NotNil(t, tlsConfig)
	assert.Equal(t, []tls.Certificate{expectedKeypair}, tlsConfig.Certificates)
	assert.Equal(t, expectedCaCertPool.Subjects(), tlsConfig.ClientCAs.Subjects())
	assert.Equal(t, tls.RequireAndVerifyClientCert, tlsConfig.ClientAuth)
	// Check that our base option is honored.
	assert.Equal(t, uint16(tls.VersionTLS13), tlsConfig.MinVersion)
	// check that the ALPN protocol is set.
	assert.Contains(t, tlsConfig.NextProtos, alpnProtocolH2)
}
