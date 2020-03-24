package oauth

import (
	"errors"
	"github.com/RichardKnop/go-oauth2-server/models"
	"github.com/RichardKnop/go-oauth2-server/oauth/tokentypes"
)

var (
	// ErrInvalidRedirectURI ...
	ErrInvalidRedirectURI = errors.New("Invalid redirect URI")
)

func (s *Service) authorizationCodeGrant(tokenRequest *TokenRequest, client *models.OauthClient) (*AccessTokenResponse, error) {
	// Fetch the authorization code
	authorizationCode, err := s.getValidAuthorizationCode(
		tokenRequest.Code,
		tokenRequest.RedirectURI,
		client,
		tokenRequest.CodeVerifier,
		tokenRequest.CodeChallengeMethod,
	)
	if err != nil {
		return nil, err
	}

	// Log in the user
	accessToken, refreshToken, err := s.Login(
		authorizationCode.Client,
		authorizationCode.User,
		authorizationCode.Scope,
	)
	if err != nil {
		return nil, err
	}

	// Delete the authorization code
	s.db.Unscoped().Delete(&authorizationCode)

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
