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

// generate jwt token
func (c Claims) Generate(secret []byte) (string, error) {
	// Encode header and claims
	headerEnc, _ := json.Marshal(map[string]string{"typ": "JWT", "alg": "HS256"})
	claimsEnc, _ := json.Marshal(c)
	jwtStr := fmt.Sprintf(
		"%s.%s",
		base64.RawURLEncoding.EncodeToString(headerEnc),
		base64.RawURLEncoding.EncodeToString(claimsEnc),
	)

	// Sign with sha 256
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(jwtStr))

	return fmt.Sprintf("%s.%s", jwtStr, base64.RawURLEncoding.EncodeToString(mac.Sum(nil))), nil
}

// grab the body and unmarshal into claims interface
func ParseClaims(tokenStr string) (Claims, error) {
	tokenArray := strings.Split(tokenStr, ".")

	claimsByte, err := base64.RawURLEncoding.DecodeString(tokenArray[1])
	if err != nil {
		return nil, err
	}

	var claims Claims
	err = json.Unmarshal(claimsByte, &claims)
	if err != nil {
		return nil, err
	}

	return claims, nil
}

// identify the signature matches
func Verify(tokenStr string, secret []byte) bool {
	token := strings.Split(tokenStr, ".")
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(fmt.Sprintf("%s.%s", token[0], token[1])))
	return hmac.Equal([]byte(token[2]), mac.Sum(nil))
}
