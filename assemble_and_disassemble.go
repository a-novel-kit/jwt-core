package jwtcore

import "strings"

// Assemble takes multiple JSON Web strings and merges them into a single one.
func Assemble(tokens ...string) string {
	return strings.Join(tokens, ".")
}

// Disassemble takes a JSON Web string and returns multiple JSON Web strings.
func Disassemble(token string) []string {
	return strings.Split(token, ".")
}
