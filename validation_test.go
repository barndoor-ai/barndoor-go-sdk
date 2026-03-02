package barndoor

import (
	"testing"
)

// ---------------------------------------------------------------------------
// validateURL
// ---------------------------------------------------------------------------

func TestValidateURL_Valid(t *testing.T) {
	got, err := validateURL("https://example.com", "test URL")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "https://example.com" {
		t.Errorf("got %q, want %q", got, "https://example.com")
	}
}

func TestValidateURL_Empty(t *testing.T) {
	_, err := validateURL("", "test URL")
	if err == nil {
		t.Fatal("expected error for empty URL")
	}
	if _, ok := err.(*ConfigurationError); !ok {
		t.Errorf("expected ConfigurationError, got %T", err)
	}
}

func TestValidateURL_WhitespaceOnly(t *testing.T) {
	_, err := validateURL("   ", "test URL")
	if err == nil {
		t.Fatal("expected error for whitespace-only URL")
	}
}

func TestValidateURL_Invalid(t *testing.T) {
	_, err := validateURL("not a url", "test URL")
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
}

// ---------------------------------------------------------------------------
// validateToken
// ---------------------------------------------------------------------------

func TestValidateToken_ValidJWT(t *testing.T) {
	token := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0In0.signature"
	got, err := validateToken(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != token {
		t.Errorf("got %q, want %q", got, token)
	}
}

func TestValidateToken_Empty(t *testing.T) {
	_, err := validateToken("")
	if err == nil {
		t.Fatal("expected error for empty token")
	}
	if _, ok := err.(*TokenError); !ok {
		t.Errorf("expected TokenError, got %T", err)
	}
}

func TestValidateToken_WhitespaceOnly(t *testing.T) {
	_, err := validateToken("   ")
	if err == nil {
		t.Fatal("expected error for whitespace-only token")
	}
}

func TestValidateToken_NotJWT(t *testing.T) {
	_, err := validateToken("not-a-jwt")
	if err == nil {
		t.Fatal("expected error for non-JWT token")
	}
}

func TestValidateToken_TwoParts(t *testing.T) {
	_, err := validateToken("header.payload")
	if err == nil {
		t.Fatal("expected error for two-part token")
	}
}

// ---------------------------------------------------------------------------
// validateServerID
// ---------------------------------------------------------------------------

func TestValidateServerID_ValidUUID(t *testing.T) {
	id := "550e8400-e29b-41d4-a716-446655440000"
	got, err := validateServerID(id)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != id {
		t.Errorf("got %q, want %q", got, id)
	}
}

func TestValidateServerID_ValidSlug(t *testing.T) {
	slug := "my-server-1"
	got, err := validateServerID(slug)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != slug {
		t.Errorf("got %q, want %q", got, slug)
	}
}

func TestValidateServerID_Empty(t *testing.T) {
	_, err := validateServerID("")
	if err == nil {
		t.Fatal("expected error for empty server ID")
	}
}

func TestValidateServerID_WhitespaceOnly(t *testing.T) {
	_, err := validateServerID("   ")
	if err == nil {
		t.Fatal("expected error for whitespace-only server ID")
	}
}

func TestValidateServerID_InvalidChars(t *testing.T) {
	_, err := validateServerID("INVALID_SLUG!")
	if err == nil {
		t.Fatal("expected error for invalid server ID")
	}
}

func TestValidateServerID_UppercaseUUID(t *testing.T) {
	// UUIDs should be accepted case-insensitively
	id := "550E8400-E29B-41D4-A716-446655440000"
	_, err := validateServerID(id)
	if err != nil {
		t.Fatalf("uppercase UUID should be valid: %v", err)
	}
}

// ---------------------------------------------------------------------------
// isUUID
// ---------------------------------------------------------------------------

func TestIsUUID_Valid(t *testing.T) {
	if !isUUID("550e8400-e29b-41d4-a716-446655440000") {
		t.Error("expected true for valid UUID")
	}
}

func TestIsUUID_UpperCase(t *testing.T) {
	if !isUUID("550E8400-E29B-41D4-A716-446655440000") {
		t.Error("expected true for uppercase UUID")
	}
}

func TestIsUUID_NotUUID(t *testing.T) {
	if isUUID("not-a-uuid") {
		t.Error("expected false for non-UUID")
	}
}

func TestIsUUID_Slug(t *testing.T) {
	if isUUID("my-server") {
		t.Error("expected false for slug")
	}
}

func TestIsUUID_Empty(t *testing.T) {
	if isUUID("") {
		t.Error("expected false for empty string")
	}
}
