package eJwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

//a generate a new claim and secret
func New(claims interface{}, secert []byte) (string, error) {
	claimsMarshaled, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	encodedClaims := base64.RawURLEncoding.EncodeToString(claimsMarshaled)
	mac := hmac.New(sha256.New, secert)
	mac.Write([]byte(encodedClaims))

	return fmt.Sprintf("%s.%s", encodedClaims, base64.RawURLEncoding.EncodeToString(mac.Sum(nil))), nil
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
