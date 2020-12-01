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

func ParseClaims(token string, claims interface{}) error {
	claimsSplited := strings.Split(token, ".")[0]

	claimsDecoded, err := base64.RawURLEncoding.DecodeString(claimsSplited)
	if err != nil {
		return err
	}

	err = json.Unmarshal(claimsDecoded, claims)
	if err != nil {
		return err
	}
	return nil
}

// test
func Verify(token string, secret []byte) bool {
	tokenSplited := strings.Split(token, ".")
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(tokenSplited[0]))
	return hmac.Equal([]byte(tokenSplited[1]), mac.Sum(nil))

}
