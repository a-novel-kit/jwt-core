package jwtcore_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	jwtcore "github.com/a-novel-kit/jwt-core"
)

func TestAssemble(t *testing.T) {
	testCases := []struct {
		name string

		tokens []string

		expect string
	}{
		{
			name: "ok",

			tokens: []string{
				"foo",
				"bar",
			},

			expect: "foo.bar",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.expect, jwtcore.Assemble(testCase.tokens...))
		})
	}
}

func TestDisassemble(t *testing.T) {
	testCases := []struct {
		name string

		token string

		expect []string
	}{
		{
			name: "ok",

			token: "foo.bar",

			expect: []string{
				"foo",
				"bar",
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.expect, jwtcore.Disassemble(testCase.token))
		})
	}
}
