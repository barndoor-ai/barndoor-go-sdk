package barndoor

import "testing"

// ---------------------------------------------------------------------------
// ServerSummary.Validate
// ---------------------------------------------------------------------------

func TestServerSummary_Validate_Valid(t *testing.T) {
	s := &ServerSummary{
		ID:               "550e8400-e29b-41d4-a716-446655440000",
		Name:             "GitHub",
		Slug:             "github",
		ConnectionStatus: ConnectionStatusAvailable,
	}
	if err := s.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestServerSummary_Validate_MissingID(t *testing.T) {
	s := &ServerSummary{Name: "GitHub", Slug: "github", ConnectionStatus: ConnectionStatusAvailable}
	if err := s.Validate(); err == nil {
		t.Fatal("expected error for missing ID")
	}
}

func TestServerSummary_Validate_MissingName(t *testing.T) {
	s := &ServerSummary{ID: "id", Slug: "github", ConnectionStatus: ConnectionStatusAvailable}
	if err := s.Validate(); err == nil {
		t.Fatal("expected error for missing Name")
	}
}

func TestServerSummary_Validate_MissingSlug(t *testing.T) {
	s := &ServerSummary{ID: "id", Name: "GitHub", ConnectionStatus: ConnectionStatusAvailable}
	if err := s.Validate(); err == nil {
		t.Fatal("expected error for missing Slug")
	}
}

func TestServerSummary_Validate_MissingStatus(t *testing.T) {
	s := &ServerSummary{ID: "id", Name: "GitHub", Slug: "github"}
	if err := s.Validate(); err == nil {
		t.Fatal("expected error for missing ConnectionStatus")
	}
}

// ---------------------------------------------------------------------------
// AgentToken.Validate
// ---------------------------------------------------------------------------

func TestAgentToken_Validate_Valid(t *testing.T) {
	at := &AgentToken{AgentToken: "token123", ExpiresIn: 3600}
	if err := at.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAgentToken_Validate_MissingToken(t *testing.T) {
	at := &AgentToken{ExpiresIn: 3600}
	if err := at.Validate(); err == nil {
		t.Fatal("expected error for missing AgentToken")
	}
}

// ---------------------------------------------------------------------------
// ConnectionStatus constants
// ---------------------------------------------------------------------------

func TestConnectionStatus_Values(t *testing.T) {
	if ConnectionStatusAvailable != "available" {
		t.Errorf("ConnectionStatusAvailable = %q", ConnectionStatusAvailable)
	}
	if ConnectionStatusPending != "pending" {
		t.Errorf("ConnectionStatusPending = %q", ConnectionStatusPending)
	}
	if ConnectionStatusConnected != "connected" {
		t.Errorf("ConnectionStatusConnected = %q", ConnectionStatusConnected)
	}
}
