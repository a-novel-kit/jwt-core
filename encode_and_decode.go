package jwtcore

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// Encode takes a payload and returns a JSON Web string.
func Encode(payload interface{}) (string, error) {
	serialized, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal payload: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(serialized), nil
}

// Decode takes a JSON Web string and returns a payload.
func Decode(token string, payload interface{}) error {
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return fmt.Errorf("decode token: %w", err)
	}

	if err := json.Unmarshal(decoded, payload); err != nil {
		return fmt.Errorf("unmarshal payload: %w", err)
	}

	return nil
}
