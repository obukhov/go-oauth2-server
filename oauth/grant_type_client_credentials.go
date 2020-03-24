package oauth

import (
	"github.com/RichardKnop/go-oauth2-server/models"
	"github.com/RichardKnop/go-oauth2-server/oauth/tokentypes"
)

func (s *Service) clientCredentialsGrant(tokenRequest *TokenRequest, client *models.OauthClient) (*AccessTokenResponse, error) {
	// Get the scope string
	scope, err := s.GetScope(tokenRequest.Scope)
	if err != nil {
		return nil, err
	}

	// Create a new access token
	accessToken, err := s.GrantAccessToken(
		client,
		nil,                             // empty user
		s.cnf.Oauth.AccessTokenLifetime, // expires in
		scope,
	)
	if err != nil {
		return nil, err
	}

	// Create response
	accessTokenResponse, err := NewAccessTokenResponse(
		accessToken,
		nil, // refresh token
		s.cnf.Oauth.AccessTokenLifetime,
		tokentypes.Bearer,
	)
	if err != nil {
		return nil, err
	}

	return accessTokenResponse, nil
}
