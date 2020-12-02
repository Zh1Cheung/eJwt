package eJwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

type Token struct {
	Header Header
	Claims interface{}
}

type Header struct {
	Type      string
	Algorithm string
}

//a generate a new claim and secret
func New(claims interface{}, secert []byte) (string, error) {
	header := &Header{
		Type:      "JWT",
		Algorithm: "SHA256",
	}
	headerMarshaled, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsMarshaled, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	jwt := fmt.Sprintf(
		"%s.%s",
		base64.RawURLEncoding.EncodeToString(headerMarshaled),
		base64.RawURLEncoding.EncodeToString(claimsMarshaled),
	)
	mac := hmac.New(sha256.New, secert)
	mac.Write([]byte(jwt))

	return fmt.Sprintf("%s.%s", jwt, base64.RawURLEncoding.EncodeToString(mac.Sum(nil))), nil
}

func ParseClaims(tokenStr string, claims interface{}) (*Token, error) {
	tokenSplit := strings.Split(tokenStr, ".")

	token := Token{}

	HeaderDecoded, err := base64.RawURLEncoding.DecodeString(tokenSplit[0])
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(HeaderDecoded, &token.Header)
	if err != nil {
		return nil, err
	}

	return &token, nil
}

// test
func (t *Token) Verify(tokenStr string, secret []byte) bool {
	token := strings.Split(tokenStr, ".")
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(token[0]))
	return hmac.Equal([]byte(token[1]), mac.Sum(nil))
}
