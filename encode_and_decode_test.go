package jwtcore_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	jwtcore "github.com/a-novel-kit/jwt-core"
)

func TestEncodeAndDecode(t *testing.T) {
	payload := map[string]any{
		"foo": "bar",
	}

	token, err := jwtcore.Encode(payload)
	require.NoError(t, err)

	var decodedPayload map[string]any

	err = jwtcore.Decode(token, &decodedPayload)
	require.NoError(t, err)

	require.Equal(t, payload, decodedPayload)
}
