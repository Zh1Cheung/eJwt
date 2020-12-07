package eJwt

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
)

const (
	TokenID   = "jti"
	Issuer    = "iss"
	Audience  = "aud"
	Subject   = "sub"
	IssuedAt  = "iat"
	ExpiresAt = "exp"
	NotBefore = "nbf"
)

// body information
type Claims map[string]interface{}

// init
func New() *Claims {
	return &Claims{}
}

// unmarshal to claims
func ToClaims(struc interface{}) (Claims, error) {
	strucBytes, _ := json.Marshal(struc)
	var claims Claims
	err := json.Unmarshal(strucBytes, &claims)
	if err != nil {
		return nil, err
	}

	return claims, nil
}

// claims to struct
func (c Claims) ToStruct(struc interface{}) error {
	claimsBytes, _ := json.Marshal(c)
	err := json.Unmarshal(claimsBytes, struc)
	if err != nil {
		return err
	}

	return nil
}

func (c Claims) AddClaim(name string, value interface{}) { c[name] = value }

func (c Claims) HasClaim(name string) bool { _, ok := c[name]; return ok }

func (c Claims) GetClaim(name string) interface{} { return c[name] }

func (c Claims) GetClaimStr(name string) string {
	if val, ok := c[name]; ok {
		return val.(string)
	}
	return ""
}

func (c Claims) GetClaimInt(name string) int {
	if val, ok := c[name]; ok {
		return val.(int)
	}
	return 0
}

func (c Claims) GetClaimFloat(name string) float32 {
	if val, ok := c[name]; ok {
		return val.(float32)
	}
	return 0
}

func (c Claims) SetTokenID() {
	c[TokenID] = UUID()
}

func (c Claims) GetTokenID() string {
	if val, ok := c[TokenID]; ok {
		return val.(string)
	}
	return ""
}

func (c Claims) SetIssuer(issuer string) {
	c[Issuer] = issuer
}

func (c Claims) GetIssuer() string {
	if val, ok := c[Issuer]; ok {
		return val.(string)
	}
	return ""
}

func (c Claims) SetAudience(audience string) {
	c[Audience] = audience
}

func (c Claims) GetAudience() string {
	if val, ok := c[Audience]; ok {
		return val.(string)
	}
	return ""
}

func (c Claims) SetSubject(subject string) {
	c[Subject] = subject
}

func (c Claims) GetSubject() string {
	if val, ok := c[Subject]; ok {
		return val.(string)
	}
	return ""
}

func (c Claims) SetIssuedAt(issuedAt int) {
	c[IssuedAt] = issuedAt
}

func (c Claims) GetIssuedAt() int {
	if val, ok := c[IssuedAt]; ok {
		return val.(int)
	}
	return 0
}

func (c Claims) SetExpiresAt(expiresAt int) {
	c[ExpiresAt] = expiresAt
}

func (c Claims) GetExpiresAt() int {
	if val, ok := c[ExpiresAt]; ok {
		return val.(int)
	}
	return 0
}

func (c Claims) SetNotBeforeAt(notbeforeAt int) {
	c[NotBefore] = notbeforeAt
}

func (c Claims) GetNotBeforeAt() int {
	if val, ok := c[NotBefore]; ok {
		return val.(int)
	}
	return 0
}

func UUID() string {
	version := byte(4)
	uuid := make([]byte, 16)
	rand.Read(uuid)

	// Set version
	uuid[6] = (uuid[6] & 0x0f) | (version << 4)

	// Set variant
	uuid[8] = (uuid[8] & 0xbf) | 0x80

	buf := make([]byte, 36)
	var dash byte = '-'
	hex.Encode(buf[0:8], uuid[0:4])
	buf[8] = dash
	hex.Encode(buf[9:13], uuid[4:6])
	buf[13] = dash
	hex.Encode(buf[14:18], uuid[6:8])
	buf[18] = dash
	hex.Encode(buf[19:23], uuid[8:10])
	buf[23] = dash
	hex.Encode(buf[24:], uuid[10:])

	return string(buf)
}
