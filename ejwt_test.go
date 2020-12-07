package eJwt

import "testing"

func TestClaims_Generate(t *testing.T) {

	Claims := New()
	Claims.AddClaim("hel", "wor")
	jwt, err := Claims.Generate([]byte("hi"))
	if err != nil {
		t.Error(err)
	}
	if jwt == "" {
		t.Error("jwt is empty")
	}
}
