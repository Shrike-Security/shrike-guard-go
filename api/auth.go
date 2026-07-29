package api

import (
	"context"
	"time"
)

// RegisterRequest is the registration request payload.
type RegisterRequest struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	CompanyName string `json:"company_name,omitempty"`
}

// LoginRequest is the login request payload.
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// AuthResponse is the authentication response with tokens.
type AuthResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

// UserProfile is the user profile response.
type UserProfile struct {
	CustomerID  string    `json:"customer_id"`
	Email       string    `json:"email"`
	CompanyName string    `json:"company_name,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// RefreshRequest is the token refresh request.
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// AuthClient is the authentication client for Shrike API.
type AuthClient struct {
	*BaseClient
}

// NewAuthClient creates a new authentication client.
func NewAuthClient(opts ClientOptions) *AuthClient {
	return &AuthClient{
		BaseClient: NewBaseClient(opts),
	}
}

// Register registers a new customer account.
func (c *AuthClient) Register(ctx context.Context, req RegisterRequest) (*AuthResponse, error) {
	var resp AuthResponse
	err := c.Post(ctx, "/api/v1/auth/register", req, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// Login logs in with email and password.
func (c *AuthClient) Login(ctx context.Context, req LoginRequest) (*AuthResponse, error) {
	var resp AuthResponse
	err := c.Post(ctx, "/api/v1/auth/login", req, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// Refresh refreshes the access token using a refresh token.
func (c *AuthClient) Refresh(ctx context.Context, refreshToken string) (*AuthResponse, error) {
	var resp AuthResponse
	err := c.Post(ctx, "/api/v1/auth/refresh", RefreshRequest{RefreshToken: refreshToken}, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// Logout logs out and invalidates the current session.
func (c *AuthClient) Logout(ctx context.Context) error {
	return c.Post(ctx, "/api/v1/auth/logout", nil, nil)
}

// Me gets the current user's profile.
func (c *AuthClient) Me(ctx context.Context) (*UserProfile, error) {
	var resp UserProfile
	err := c.Get(ctx, "/api/v1/auth/me", &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}
