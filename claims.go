package eJwt

import "encoding/json"

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
