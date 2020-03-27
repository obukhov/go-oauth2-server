package oauth

import (
	"errors"
	"net/http"

	"github.com/RichardKnop/go-oauth2-server/models"
	"github.com/RichardKnop/go-oauth2-server/oauth/tokentypes"
)

const (
	// AccessTokenHint ...
	AccessTokenHint = "access_token"
	// RefreshTokenHint ...
	RefreshTokenHint = "refresh_token"
)

var (
	// ErrTokenMissing ...
	ErrTokenMissing = errors.New("Token missing")
	// ErrTokenHintInvalid ...
	ErrTokenHintInvalid = errors.New("Invalid token hint")
)

// IntrospectionRequest ...
type IntrospectionRequest struct {
	ClientID      string `schema:"client_id" json:"client_id"`
	ClientSecret  string `schema:"client_secret" json:"client_secret"`
	Token         string `schema:"token" json:"token"`
	TokenTypeHint string `schema:"token_type_hint" json:"token_type_hint"`
}

func (s *Service) introspectToken(r *http.Request, client *models.OauthClient) (*IntrospectResponse, error) {
	var (
		introspectionRequest IntrospectionRequest
		err                  error
	)

	err = s.DecodeRequest(r, &introspectionRequest)
	if err != nil {
		return nil, err
	}

	if introspectionRequest.Token == "" {
		return nil, ErrTokenMissing
	}

	// Default to access token hint
	if introspectionRequest.TokenTypeHint == "" {
		introspectionRequest.TokenTypeHint = AccessTokenHint
	}

	switch introspectionRequest.TokenTypeHint {
	case AccessTokenHint:
		accessToken, err := s.Authenticate(introspectionRequest.Token)
		if err != nil {
			return nil, err
		}
		return s.NewIntrospectResponseFromAccessToken(accessToken)
	case RefreshTokenHint:
		refreshToken, err := s.GetValidRefreshToken(introspectionRequest.Token, client)
		if err != nil {
			return nil, err
		}
		return s.NewIntrospectResponseFromRefreshToken(refreshToken)
	default:
		return nil, ErrTokenHintInvalid
	}
}

// NewIntrospectResponseFromAccessToken ...
func (s *Service) NewIntrospectResponseFromAccessToken(accessToken *models.OauthAccessToken) (*IntrospectResponse, error) {
	var introspectResponse = &IntrospectResponse{
		Active:    true,
		Scope:     accessToken.Scope,
		TokenType: tokentypes.Bearer,
		ExpiresAt: int(accessToken.ExpiresAt.Unix()),
	}

	if accessToken.ClientID.Valid {
		client := new(models.OauthClient)
		notFound := s.db.Select("key").First(client, accessToken.ClientID.String).
			RecordNotFound()
		if notFound {
			return nil, ErrClientNotFound
		}
		introspectResponse.ClientID = client.Key
	}

	if accessToken.UserID.Valid {
		user := new(models.OauthUser)
		notFound := s.db.Select("username").Where("id = ?", accessToken.UserID.String).
			First(user, accessToken.UserID.String).RecordNotFound()
		if notFound {
			return nil, ErrUserNotFound
		}
		introspectResponse.Username = user.Username
	}

	return introspectResponse, nil
}

// NewIntrospectResponseFromRefreshToken ...
func (s *Service) NewIntrospectResponseFromRefreshToken(refreshToken *models.OauthRefreshToken) (*IntrospectResponse, error) {
	var introspectResponse = &IntrospectResponse{
		Active:    true,
		Scope:     refreshToken.Scope,
		TokenType: tokentypes.Bearer,
		ExpiresAt: int(refreshToken.ExpiresAt.Unix()),
	}

	if refreshToken.ClientID.Valid {
		client := new(models.OauthClient)
		notFound := s.db.Select("key").First(client, refreshToken.ClientID.String).
			RecordNotFound()
		if notFound {
			return nil, ErrClientNotFound
		}
		introspectResponse.ClientID = client.Key
	}

	if refreshToken.UserID.Valid {
		user := new(models.OauthUser)
		notFound := s.db.Select("username").Where("id = ?", refreshToken.UserID.String).
			First(user, refreshToken.UserID.String).RecordNotFound()
		if notFound {
			return nil, ErrUserNotFound
		}
		introspectResponse.Username = user.Username
	}

	return introspectResponse, nil
}
