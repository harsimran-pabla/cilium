// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package encrypt

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_IsIPsecAlgoSupported(t *testing.T) {
	testCases := []struct {
		have     string
		expected bool
	}{
		{
			have:     "",
			expected: true,
		},
		{
			have:     "rfc4106-gcm-aes",
			expected: true,
		},
		{
			have:     "cbc-aes-sha256",
			expected: true,
		},
		{
			have:     "cbc-aes-sha512",
			expected: true,
		},
		{
			have:     "bla-bla",
			expected: false,
		},
	}

	for _, tt := range testCases {
		// function to test
		actual := IsIPsecAlgoSupported(tt.have)

		require.Equal(t, tt.expected, actual)
	}
}

func Test_rotateIPsecKey(t *testing.T) {
	testCases := []struct {
		haveKey  ipsecKey
		haveAlgo string
		expected ipsecKey
	}{
		{
			haveAlgo: "",
			haveKey: ipsecKey{
				spi:  3,
				algo: "rfc4106(gcm(aes))",
				key:  "41049390e1e2b5d6543901daab6435f4042155fe",
				size: 128,
			},
			expected: ipsecKey{
				spi:  4,
				algo: "rfc4106(gcm(aes))",
				key:  "41049390e1e2b5d6543901daab6435f4042155fe",
				size: 128,
			},
		},
		{
			haveAlgo: "",
			haveKey: ipsecKey{
				spi:  16,
				algo: "rfc4106(gcm(aes))",
				key:  "41049390e1e2b5d6543901daab6435f4042155fe",
				size: 128,
			},
			expected: ipsecKey{
				spi:  1,
				algo: "rfc4106(gcm(aes))",
				key:  "41049390e1e2b5d6543901daab6435f4042155fe",
				size: 128,
			},
		},
		{
			haveAlgo: "",
			haveKey: ipsecKey{
				spi:        3,
				algo:       "hmac(sha256)",
				key:        "e6b4bab427cd37bb64b39cd66a8476a62963174b78bc544fb525f4c2f548342b",
				cipherMode: "cbc(aes)",
				cipherKey:  "0f12337d9ee75095ff21402dc98476f5f9107261073b70bb37747237d2691d3e",
			},
			expected: ipsecKey{
				spi:        4,
				algo:       "hmac(sha256)",
				key:        "e6b4bab427cd37bb64b39cd66a8476a62963174b78bc544fb525f4c2f548342b",
				cipherMode: "cbc(aes)",
				cipherKey:  "0f12337d9ee75095ff21402dc98476f5f9107261073b70bb37747237d2691d3e",
			},
		},
		{
			haveAlgo: "",
			haveKey: ipsecKey{
				spi:        16,
				algo:       "hmac(sha256)",
				key:        "e6b4bab427cd37bb64b39cd66a8476a62963174b78bc544fb525f4c2f548342b",
				cipherMode: "cbc(aes)",
				cipherKey:  "0f12337d9ee75095ff21402dc98476f5f9107261073b70bb37747237d2691d3e",
			},
			expected: ipsecKey{
				spi:        1,
				algo:       "hmac(sha256)",
				key:        "e6b4bab427cd37bb64b39cd66a8476a62963174b78bc544fb525f4c2f548342b",
				cipherMode: "cbc(aes)",
				cipherKey:  "0f12337d9ee75095ff21402dc98476f5f9107261073b70bb37747237d2691d3e",
			},
		},
		{
			haveAlgo: "rfc4106-gcm-aes",
			haveKey: ipsecKey{
				spi: 16,
			},
			expected: ipsecKey{
				spi:  1,
				algo: "rfc4106(gcm(aes))",
				key:  "41049390e1e2b5d6543901daab6435f4042155fe",
				size: 128,
			},
		},
		{
			haveAlgo: "cbc-aes-sha256",
			haveKey: ipsecKey{
				spi: 3,
			},
			expected: ipsecKey{
				spi:        4,
				algo:       "hmac(sha256)",
				key:        "a9d204b6c2df6f0b707bbfdb71b4bd44",
				cipherMode: "cbc(aes)",
				cipherKey:  "9bd24c14452783bb6f3c9335aff2ed2e",
			},
		},
		{
			haveAlgo: "cbc-aes-sha512",
			haveKey: ipsecKey{
				spi: 4,
			},
			expected: ipsecKey{
				spi:        5,
				algo:       "hmac(sha512)",
				key:        "8b4d92bf9396e7febb4d51e87394bb158ebcc0d9d57e4da8e938b0e931223ec7",
				cipherMode: "cbc(aes)",
				cipherKey:  "0151a41da39e3310d4f58b3930788dc4",
			},
		},
	}

	for _, tt := range testCases {
		// function to test
		actual, err := rotateIPsecKey(tt.haveKey, tt.haveAlgo)

		require.NoError(t, err)
		require.Equal(t, tt.expected.spi, actual.spi)
		require.Equal(t, tt.expected.algo, actual.algo)
		require.Len(t, actual.key, len(tt.expected.key))
		require.Len(t, actual.cipherKey, len(tt.expected.cipherKey))
		require.Equal(t, tt.expected.size, actual.size)
		require.Equal(t, tt.expected.cipherMode, actual.cipherMode)
		if tt.expected.cipherMode == "" {
			// this field will be randomly generated, `require.NotEqual` used for verification
			require.NotEqual(t, tt.expected.key, actual.key)
			require.Equal(t, tt.expected.cipherKey, actual.cipherKey)
		} else {
			// the following fields will be randomly generated, `require.NotEqual` used for verification
			require.NotEqual(t, tt.expected.key, actual.key)
			require.NotEqual(t, tt.expected.cipherKey, actual.cipherKey)
		}
	}
}
