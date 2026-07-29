package api

import (
	"context"
	"testing"

	"github.com/shrike-security/shrike-guard-go/internal/testutil"
)

func TestAuthClient_Login(t *testing.T) {
	server := testutil.NewMockServer()
	defer server.Close()

	client := NewAuthClient(ClientOptions{
		BaseURL: server.URL(),
	})

	t.Run("login with valid credentials", func(t *testing.T) {
		resp, err := client.Login(context.Background(), LoginRequest{
			Email:    "test@example.com",
			Password: "password123",
		})

		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if resp.AccessToken != "mock-access-token" {
			t.Errorf("Expected access token, got %s", resp.AccessToken)
		}
		if resp.RefreshToken != "mock-refresh-token" {
			t.Errorf("Expected refresh token, got %s", resp.RefreshToken)
		}
		if resp.TokenType != "Bearer" {
			t.Errorf("Expected Bearer token type, got %s", resp.TokenType)
		}
	})

	t.Run("login with invalid credentials", func(t *testing.T) {
		_, err := client.Login(context.Background(), LoginRequest{
			Email:    "wrong@example.com",
			Password: "wrongpassword",
		})

		if err == nil {
			t.Fatal("Expected error for invalid credentials")
		}
	})
}

func TestAuthClient_Register(t *testing.T) {
	server := testutil.NewMockServer()
	defer server.Close()

	client := NewAuthClient(ClientOptions{
		BaseURL: server.URL(),
	})

	t.Run("register new user", func(t *testing.T) {
		resp, err := client.Register(context.Background(), RegisterRequest{
			Email:       "newuser@example.com",
			Password:    "securepassword123",
			CompanyName: "New Company",
		})

		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if resp.AccessToken == "" {
			t.Error("Expected access token")
		}
		if resp.RefreshToken == "" {
			t.Error("Expected refresh token")
		}
	})
}

func TestAuthClient_Me(t *testing.T) {
	server := testutil.NewMockServer()
	defer server.Close()

	client := NewAuthClient(ClientOptions{
		BaseURL: server.URL(),
		APIKey:  "mock-access-token",
	})

	t.Run("get current user profile", func(t *testing.T) {
		profile, err := client.Me(context.Background())

		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if profile.CustomerID != "cust_123" {
			t.Errorf("Expected customer ID, got %s", profile.CustomerID)
		}
		if profile.Email != "test@example.com" {
			t.Errorf("Expected email, got %s", profile.Email)
		}
		if profile.CompanyName != "Test Company" {
			t.Errorf("Expected company name, got %s", profile.CompanyName)
		}
	})
}

func TestAuthFlow_Integration(t *testing.T) {
	server := testutil.NewMockServer()
	defer server.Close()

	client := NewAuthClient(ClientOptions{
		BaseURL: server.URL(),
	})

	// 1. Register
	registerResp, err := client.Register(context.Background(), RegisterRequest{
		Email:    "flowtest@example.com",
		Password: "testpassword123",
	})
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}
	if registerResp.AccessToken == "" {
		t.Fatal("Expected access token from register")
	}

	// 2. Login
	loginResp, err := client.Login(context.Background(), LoginRequest{
		Email:    "test@example.com",
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	if loginResp.AccessToken == "" {
		t.Fatal("Expected access token from login")
	}

	// 3. Get profile with access token
	authenticatedClient := NewAuthClient(ClientOptions{
		BaseURL: server.URL(),
		APIKey:  loginResp.AccessToken,
	})

	profile, err := authenticatedClient.Me(context.Background())
	if err != nil {
		t.Fatalf("Get profile failed: %v", err)
	}
	if profile.Email == "" {
		t.Fatal("Expected email in profile")
	}
}
