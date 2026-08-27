package barndoor

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// channelsPath is the platform path for the public notification channel-management
// surface (BCP-3758). Every call is organization-scoped from the caller's token —
// there is no organization parameter.
const channelsPath = "/api/notification/public/v1/channels"

// ChannelType is the kind of destination a notification channel delivers to.
//
// The type discriminates the whole model: it decides which destination field is
// required, whether the channel is personal (owned by one user) or organization-wide,
// and which natural-identity key an upsert without an ID dedupes on.
type ChannelType string

const (
	// ChannelTypeInApp delivers to the owner's notification inbox in the platform UI.
	// Personal: the owner is always the authenticated caller.
	ChannelTypeInApp ChannelType = "in_app"
	// ChannelTypeUserEmail delivers to the owner's own account email. Personal.
	ChannelTypeUserEmail ChannelType = "user_email"
	// ChannelTypeEmail delivers to an arbitrary address (a team alias, a ticketing
	// inbox). Organization-wide; requires EmailAddress.
	ChannelTypeEmail ChannelType = "email"
	// ChannelTypeWebhook delivers to an HTTPS endpoint you own, signed with a
	// Standard Webhooks secret. Organization-wide; requires URL.
	ChannelTypeWebhook ChannelType = "webhook"
	// ChannelTypeSlack delivers to a channel in the organization's connected Slack
	// workspace. Requires SlackChannelID and Label, and the Slack app must already be
	// installed (an interactive flow that is not part of this API).
	ChannelTypeSlack ChannelType = "slack"
	// ChannelTypeTeams delivers to a Microsoft Teams channel behind a Workflows
	// incoming-webhook URL. Requires Label, plus TeamsWorkflowURL on create.
	ChannelTypeTeams ChannelType = "teams"
)

// ChannelSubscription is one alert type a channel is subscribed to.
type ChannelSubscription struct {
	// AlertType is the alert type delivered to the channel (e.g. "break_glass_used").
	// Read the live vocabulary from GetChannelOptions rather than hardcoding it — the
	// set grows over time and is gated per organization.
	AlertType string `json:"alert_type"`
}

// Channel is a notification delivery destination.
//
// Only the destination field belonging to Type is populated; the rest are nil.
// Secrets are never returned — a webhook's signing secret and a Teams workflow URL
// surface only as the HasSigningSecret / HasWorkflowURL flags.
type Channel struct {
	// ID is the server-assigned channel id.
	ID string `json:"id"`
	// Type is the kind of destination.
	Type ChannelType `json:"type"`
	// Enabled reports whether the channel currently delivers.
	Enabled bool `json:"enabled"`
	// UserID is the owning user for a personal channel; nil for organization-wide types.
	UserID *string `json:"user_id,omitempty"`
	// EmailAddress is the destination for ChannelTypeEmail.
	EmailAddress *string `json:"email_address,omitempty"`
	// URL is the destination for ChannelTypeWebhook.
	URL *string `json:"url,omitempty"`
	// Label is a human-readable name, set for slack and teams channels.
	Label *string `json:"label,omitempty"`
	// SlackChannelID is the Slack channel id for ChannelTypeSlack.
	SlackChannelID *string `json:"slack_channel_id,omitempty"`
	// Subscriptions are the alert types this channel delivers. Empty means it
	// delivers nothing.
	Subscriptions []ChannelSubscription `json:"subscriptions"`
	CreatedAt     string                `json:"created_at,omitempty"`
	UpdatedAt     string                `json:"updated_at,omitempty"`
	// HasSigningSecret reports whether a webhook channel has a stored signing secret.
	// The secret itself is never readable back.
	HasSigningSecret bool `json:"has_signing_secret"`
	// HasWorkflowURL reports whether a teams channel has a stored Workflows URL
	// (itself a secret, never returned).
	HasWorkflowURL bool `json:"has_workflow_url"`
	// SigningSecret is the one-time reveal of a newly generated webhook signing
	// secret. Populated ONLY on the response that created it, and nil on every later
	// read — store it when you receive it, or rotate with RegenerateChannelSecret.
	SigningSecret *string `json:"signing_secret,omitempty"`
}

// Validate checks that required fields are present.
func (c *Channel) Validate() error {
	if c.ID == "" || c.Type == "" {
		return fmt.Errorf("Channel missing required fields")
	}
	return nil
}

// channelListResponse is the envelope the channel list endpoints return.
type channelListResponse struct {
	Data []Channel `json:"data"`
}

// AlertTypeOption is one subscribable alert type, with its intrinsic category and
// severity. Both are properties of the alert type itself, not per-channel settings.
type AlertTypeOption struct {
	// Value is what to send as a subscription's AlertType.
	Value string `json:"value"`
	// Label is a human-readable label for display.
	Label string `json:"label"`
	// Category is the type's category. Intrinsic to the type, not configurable.
	Category string `json:"category"`
	// Severity is the type's severity ("info", "warning", "critical"). Also intrinsic.
	Severity string `json:"severity"`
}

// LabeledOption is an enum value paired with its display label.
type LabeledOption struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

// ChannelOptions is the subscription vocabulary a channel's subscriptions may draw
// from.
//
// AlertTypes is filtered to what the caller's organization is admitted to —
// subscribing to a type absent here is accepted but never delivers.
type ChannelOptions struct {
	// AlertTypes is every alert type this organization may subscribe a channel to.
	AlertTypes []AlertTypeOption `json:"alert_types"`
	// Categories is the full category vocabulary, unfiltered.
	Categories []LabeledOption `json:"categories"`
	// Severities is the full severity vocabulary, unfiltered.
	Severities []LabeledOption `json:"severities"`
}

// ChannelTestResult is the result of sending a connectivity-test message through a
// channel's real transport.
//
// A transport failure is reported here as OK=false with a reason, not as an error
// return: the request to test succeeded, the delivery is what failed.
type ChannelTestResult struct {
	// OK reports whether the test message reached the destination transport.
	OK bool `json:"ok"`
	// Error is why delivery failed, when OK is false.
	Error *string `json:"error,omitempty"`
}

// WebhookSecret is the one-time reveal of a webhook channel's signing secret.
type WebhookSecret struct {
	// SigningSecret is a Standard Webhooks secret ("whsec_" + base64), shown exactly
	// once. Rotating invalidates the previous secret immediately, so deploy this value
	// before the next alert fires.
	SigningSecret string `json:"signing_secret"`
}

// UpsertChannelInput describes a channel to create or update.
//
// Which destination fields are permitted depends on Type; sending one that does not
// belong is a 422 from the server rather than a silently ignored field:
//
//	in_app / user_email  no destination fields
//	email                EmailAddress
//	webhook              URL
//	slack                SlackChannelID + Label
//	teams                Label (+ TeamsWorkflowURL on create)
type UpsertChannelInput struct {
	// Type is the kind of destination. Required.
	Type ChannelType
	// ChannelID is an existing channel to edit authoritatively. Empty means
	// create-or-dedup on the type's natural identity. When set and unknown — or owned
	// by another organization — the call returns an *HTTPError with status 404.
	ChannelID string
	// Enabled controls whether the channel delivers. Nil defaults to true. Setting it
	// to false suspends delivery while keeping the channel and its subscriptions —
	// the reversible alternative to deleting it.
	Enabled *bool
	// EmailAddress is the destination for ChannelTypeEmail.
	EmailAddress string
	// URL is the destination for ChannelTypeWebhook. Must be https and resolve to a
	// public address.
	URL string
	// Label is a human-readable name. Required for slack and teams.
	Label string
	// SlackChannelID is the Slack channel id (not its name) for ChannelTypeSlack.
	SlackChannelID string
	// TeamsWorkflowURL is the Teams Workflows URL for ChannelTypeTeams. Write-only:
	// never returned by any endpoint. Required on create, optional when editing by ID
	// (omit to keep the stored URL).
	TeamsWorkflowURL string
	// Subscriptions is the complete set of alert types to deliver. It REPLACES the
	// channel's existing set — a nil or empty slice unsubscribes it from everything.
	// At most one entry per alert type.
	Subscriptions []string
}

// GetChannelOptions lists the alert types this organization may subscribe a channel to.
//
// Read this before building a subscription set: the alert-type vocabulary grows over
// time and is gated per organization, so this endpoint — not a hardcoded list — is the
// authoritative answer to what Subscriptions accepts. Subscribing to a type absent
// here is accepted but never delivers.
func (s *BarndoorSDK) GetChannelOptions(ctx context.Context) (*ChannelOptions, error) {
	s.logger.Debug("Fetching notification channel options")

	respData, err := s.req(ctx, "GET", channelsPath+"/options", nil)
	if err != nil {
		return nil, err
	}

	var options ChannelOptions
	if err := json.Unmarshal(respData, &options); err != nil {
		return nil, fmt.Errorf("failed to parse channel options response: %w", err)
	}
	return &options, nil
}

// ListChannels lists the organization's shared notification channels.
//
// Returns the organization-wide channels — email, webhook, slack, teams — with their
// current subscription sets. Personal channels are not included; use ListUserChannels
// for those. Secrets are never returned.
func (s *BarndoorSDK) ListChannels(ctx context.Context) ([]Channel, error) {
	s.logger.Debug("Listing organization notification channels")
	return s.listChannels(ctx, channelsPath)
}

// ListUserChannels lists the caller's own personal notification channels.
//
// Returns the authenticated caller's in_app and user_email channels. Always
// self-scoped — there is no way to read another user's personal channels, and no user
// parameter to pass.
func (s *BarndoorSDK) ListUserChannels(ctx context.Context) ([]Channel, error) {
	s.logger.Debug("Listing caller's personal notification channels")
	return s.listChannels(ctx, channelsPath+"/user")
}

// listChannels fetches and unwraps the shared {"data": [...]} envelope.
func (s *BarndoorSDK) listChannels(ctx context.Context, path string) ([]Channel, error) {
	respData, err := s.req(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var envelope channelListResponse
	if err := json.Unmarshal(respData, &envelope); err != nil {
		return nil, fmt.Errorf("failed to parse channel list response: %w", err)
	}
	return envelope.Data, nil
}

// UpsertChannel creates or updates a notification channel and replaces its
// subscriptions.
//
// This is a full upsert, not a patch: Subscriptions REPLACES the channel's existing
// set, so leaving it nil removes every subscription the channel had. Send the complete
// desired set on every call — which is what makes the endpoint safe to drive from a
// declarative tool.
//
// Without ChannelID the channel is keyed on its type's natural identity, so repeating
// an identical call is idempotent rather than creating duplicates: email by address,
// webhook by URL, slack by channel id, and the personal types by (organization, type,
// caller). With ChannelID it is an authoritative edit of that row — the only way to
// update a teams channel, whose natural identity is a secret URL.
//
// When this call creates a webhook channel, the returned Channel's SigningSecret
// carries the one-time reveal — store it. A retried create that lands after the first
// attempt already succeeded returns a nil SigningSecret rather than a second secret;
// use RegenerateChannelSecret if you need one.
func (s *BarndoorSDK) UpsertChannel(ctx context.Context, input UpsertChannelInput) (*Channel, error) {
	if strings.TrimSpace(string(input.Type)) == "" {
		return nil, fmt.Errorf("channel type must not be empty")
	}

	enabled := true
	if input.Enabled != nil {
		enabled = *input.Enabled
	}

	body := map[string]any{
		"type":    string(input.Type),
		"enabled": enabled,
	}
	if input.ChannelID != "" {
		id, err := validateChannelID(input.ChannelID)
		if err != nil {
			return nil, err
		}
		body["id"] = id
	}
	// Only send destination fields the caller actually set: padding the body with
	// empty values for the other types' fields is a 422 server-side.
	for key, value := range map[string]string{
		"email_address":      input.EmailAddress,
		"url":                input.URL,
		"label":              input.Label,
		"slack_channel_id":   input.SlackChannelID,
		"teams_workflow_url": input.TeamsWorkflowURL,
	} {
		if value != "" {
			body[key] = value
		}
	}
	// Always send the key. An omitted list and an empty list mean the same thing to
	// this endpoint (unsubscribe from everything), and being explicit keeps that
	// destructive default visible on the wire instead of relying on server defaulting.
	subscriptions := make([]map[string]string, 0, len(input.Subscriptions))
	for _, alertType := range input.Subscriptions {
		subscriptions = append(subscriptions, map[string]string{"alert_type": alertType})
	}
	body["subscriptions"] = subscriptions

	s.logger.Info(fmt.Sprintf("Upserting notification channel (type=%s)", input.Type))

	respData, err := s.req(ctx, "PUT", channelsPath, &httpRequestOptions{JSON: body})
	if err != nil {
		return nil, err
	}

	var channel Channel
	if err := json.Unmarshal(respData, &channel); err != nil {
		return nil, fmt.Errorf("failed to parse channel response: %w", err)
	}
	return &channel, nil
}

// DeleteChannel deletes a notification channel.
//
// Its subscriptions cascade and any stored secret is removed. Irreversible — to stop
// delivery reversibly, call UpsertChannel with Enabled set to false.
//
// Returns an *HTTPError with status 404 when no such channel exists in the caller's
// organization.
func (s *BarndoorSDK) DeleteChannel(ctx context.Context, channelID string) error {
	id, err := validateChannelID(channelID)
	if err != nil {
		return err
	}

	s.logger.Info(fmt.Sprintf("Deleting notification channel %s", id))

	// The endpoint answers 204 with no body; req returns the raw bytes and we do not
	// unmarshal, so an empty body is fine here.
	if _, err := s.req(ctx, "DELETE", fmt.Sprintf("%s/%s", channelsPath, id), nil); err != nil {
		return err
	}
	return nil
}

// RegenerateChannelSecret rotates a webhook channel's signing secret.
//
// The new secret is returned once. The previous secret stops verifying immediately, so
// deploy the new one to your receiver before the next alert fires. There is no endpoint
// that reads the current secret, so this is also the recovery path when the secret from
// channel creation was lost.
func (s *BarndoorSDK) RegenerateChannelSecret(ctx context.Context, channelID string) (*WebhookSecret, error) {
	id, err := validateChannelID(channelID)
	if err != nil {
		return nil, err
	}

	s.logger.Info(fmt.Sprintf("Rotating signing secret for notification channel %s", id))

	respData, err := s.req(ctx, "POST", fmt.Sprintf("%s/%s/regenerate-secret", channelsPath, id), nil)
	if err != nil {
		return nil, err
	}

	var secret WebhookSecret
	if err := json.Unmarshal(respData, &secret); err != nil {
		return nil, fmt.Errorf("failed to parse webhook secret response: %w", err)
	}
	return &secret, nil
}

// TestChannel sends a stock connectivity-test message through a channel's real
// transport, so you can verify a webhook receiver, email address, Slack channel, or
// Teams workflow actually works.
//
// It is not an alert: nothing is persisted, no other channel is notified, and it does
// not depend on the channel's subscriptions.
//
// A transport failure comes back as a result with OK=false and an Error string, not as
// a non-nil error — the request succeeded, the delivery did not.
func (s *BarndoorSDK) TestChannel(ctx context.Context, channelID string) (*ChannelTestResult, error) {
	id, err := validateChannelID(channelID)
	if err != nil {
		return nil, err
	}

	s.logger.Debug(fmt.Sprintf("Testing notification channel %s", id))

	respData, err := s.req(ctx, "POST", fmt.Sprintf("%s/%s/test", channelsPath, id), nil)
	if err != nil {
		return nil, err
	}

	var result ChannelTestResult
	if err := json.Unmarshal(respData, &result); err != nil {
		return nil, fmt.Errorf("failed to parse channel test response: %w", err)
	}
	return &result, nil
}

// validateChannelID validates and normalizes a channel id.
func validateChannelID(channelID string) (string, error) {
	trimmed := strings.TrimSpace(channelID)
	if trimmed == "" {
		return "", fmt.Errorf("channel ID must be a non-empty string")
	}
	return trimmed, nil
}
