package barndoor

import "fmt"

// ConnectionStatus represents the connection status of an MCP server.
type ConnectionStatus string

const (
	ConnectionStatusAvailable ConnectionStatus = "available"
	ConnectionStatusPending   ConnectionStatus = "pending"
	ConnectionStatusConnected ConnectionStatus = "connected"
)

// ServerSummary represents summary information about an MCP server.
type ServerSummary struct {
	// ID is the unique identifier (UUID) for the server.
	ID string `json:"id"`
	// Name is the human-readable name of the server.
	Name string `json:"name"`
	// Slug is the URL-friendly identifier used in API paths.
	Slug string `json:"slug"`
	// Provider is the third-party provider name (e.g., "github", "slack").
	Provider *string `json:"provider,omitempty"`
	// ConnectionStatus is the current connection status.
	ConnectionStatus ConnectionStatus `json:"connection_status"`
}

// Validate checks that required fields are present.
func (s *ServerSummary) Validate() error {
	if s.ID == "" || s.Name == "" || s.Slug == "" || s.ConnectionStatus == "" {
		return fmt.Errorf("ServerSummary missing required fields")
	}
	return nil
}

// ServerDetail contains detailed information about an MCP server.
type ServerDetail struct {
	ServerSummary
	// URL is the MCP base URL from the server directory.
	URL *string `json:"url,omitempty"`
}

// AgentToken represents a response from the agent token exchange endpoint.
type AgentToken struct {
	// AgentToken is the agent access token.
	AgentToken string `json:"agent_token"`
	// ExpiresIn is the token lifetime in seconds.
	ExpiresIn int `json:"expires_in"`
}

// Validate checks that required fields are present.
func (t *AgentToken) Validate() error {
	if t.AgentToken == "" {
		return fmt.Errorf("AgentToken missing required fields")
	}
	return nil
}

// TokenData represents token data for storage.
type TokenData struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// paginationMetadata contains pagination information from API responses.
type paginationMetadata struct {
	Page         int  `json:"page"`
	Limit        int  `json:"limit"`
	Total        int  `json:"total"`
	Pages        int  `json:"pages"`
	PreviousPage *int `json:"previous_page"`
	NextPage     *int `json:"next_page"`
}

// paginatedResponse represents a paginated API response.
type paginatedResponse struct {
	Data       []ServerSummary    `json:"data"`
	Pagination paginationMetadata `json:"pagination"`
}

// connectionInitiationResponse is returned when initiating an OAuth connection.
type connectionInitiationResponse struct {
	AuthURL string `json:"auth_url,omitempty"`
}

// connectionStatusResponse is returned from a connection status check.
type connectionStatusResponse struct {
	Status string `json:"status"`
}
