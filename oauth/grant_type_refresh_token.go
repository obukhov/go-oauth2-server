package oauth

import (
	"github.com/RichardKnop/go-oauth2-server/models"
	"github.com/RichardKnop/go-oauth2-server/oauth/tokentypes"
)

func (s *Service) refreshTokenGrant(tokenRequest *TokenRequest, client *models.OauthClient) (*AccessTokenResponse, error) {
	// Fetch the refresh token
	theRefreshToken, err := s.GetValidRefreshToken(tokenRequest.RefreshToken, client)
	if err != nil {
		return nil, err
	}

	// Get the scope
	scope, err := s.getRefreshTokenScope(theRefreshToken, tokenRequest.Scope)
	if err != nil {
		return nil, err
	}

	// Log in the user
	accessToken, refreshToken, err := s.Login(
		theRefreshToken.Client,
		theRefreshToken.User,
		scope,
	)
	if err != nil {
		return nil, err
	}

	// Create response
	accessTokenResponse, err := NewAccessTokenResponse(
		accessToken,
		refreshToken,
		s.cnf.Oauth.AccessTokenLifetime,
		tokentypes.Bearer,
	)
	if err != nil {
		return nil, err
	}

	return accessTokenResponse, nil
}
