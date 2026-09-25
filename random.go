package barndoor

import (
	"crypto/rand"
	"encoding/base64"
)

// randomState is the OAuth state parameter. The error is returned rather than
// swallowed: predictable state turns a CSRF defence into decoration.
func randomState() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
