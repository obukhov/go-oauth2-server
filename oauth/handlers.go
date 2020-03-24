package oauth

import (
	"errors"
	"github.com/gorilla/schema"
	"net/http"

	"github.com/RichardKnop/go-oauth2-server/models"
	"github.com/RichardKnop/go-oauth2-server/util/response"
)

var (
	// ErrInvalidGrantType ...
	ErrInvalidGrantType = errors.New("Invalid grant type")
	// ErrInvalidClientIDOrSecret ...
	ErrInvalidClientIDOrSecret = errors.New("Invalid client ID or secret")
)

// TokenRequest ...
type TokenRequest struct {
	GrantType           string `schema:"grant_type" json:"grant_type"`
	CodeVerifier        string `schema:"code_verifier" json:"code_verifier"`
	CodeChallengeMethod string `schema:"code_challenge_method" json:"code_challenge_method"`
	ClientID            string `schema:"client_id" json:"client_id"`
	ClientSecret        string `schema:"client_secret" json:"client_secret"`
	RefreshToken        string `schema:"refresh_token" json:"refresh_token"`
	Scope               string `schema:"scope" json:"scope"`
	Username            string `schema:"username" json:"username"`
	Password            string `schema:"password" json:"password"`
	Code                string `schema:"code" json:"code"`
	RedirectURI         string `schema:"redirect_uri" json:"redirect_uri"`
}

var decoder = schema.NewDecoder()

// tokensHandler handles all OAuth 2.0 grant types
// (POST /v1/oauth/tokens)
func (s *Service) tokensHandler(w http.ResponseWriter, r *http.Request) {
	var (
		client       *models.OauthClient
		tokenRequest TokenRequest
		err          error
	)

	err = s.DecodeRequest(r, &tokenRequest)
	if err != nil {
		response.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Map of grant types against handler functions
	grantTypes := map[string]func(tokenRequest *TokenRequest, client *models.OauthClient) (*AccessTokenResponse, error){
		"authorization_code": s.authorizationCodeGrant,
		"password":           s.passwordGrant,
		"client_credentials": s.clientCredentialsGrant,
		"refresh_token":      s.refreshTokenGrant,
	}

	// Check the grant type
	grantHandler, ok := grantTypes[tokenRequest.GrantType]
	if !ok {
		response.Error(w, ErrInvalidGrantType.Error(), http.StatusBadRequest)
		return
	}

	// If PKCE Request, skip basic auth
	if !(tokenRequest.GrantType == "authorization_code" && len(tokenRequest.CodeVerifier) > 0) {
		// Client auth
		client, err = s.basicAuthClient(r)
		if err != nil {
			response.UnauthorizedError(w, err.Error())
			return
		}
	} else {
		client, err = s.FindClientByClientID(tokenRequest.ClientID)
		if err != nil {
			response.UnauthorizedError(w, err.Error())
			return
		}

		if !client.Public {
			response.UnauthorizedError(w, ErrPKCENotAllowed.Error())
			return
		}
	}

	// Grant processing
	resp, err := grantHandler(&tokenRequest, client)
	if err != nil {
		response.Error(w, err.Error(), getErrStatusCode(err))
		return
	}

	// Write response to json
	response.WriteJSON(w, resp, 200)
}

// introspectHandler handles OAuth 2.0 introspect request
// (POST /v1/oauth/introspect)
func (s *Service) introspectHandler(w http.ResponseWriter, r *http.Request) {
	// Client auth
	client, err := s.basicAuthClient(r)
	if err != nil {
		response.UnauthorizedError(w, err.Error())
		return
	}

	// Introspect the token
	resp, err := s.introspectToken(r, client)
	if err != nil {
		response.Error(w, err.Error(), getErrStatusCode(err))
		return
	}

	// Write response to json
	response.WriteJSON(w, resp, 200)
}

// Get client credentials from basic auth and try to authenticate client
func (s *Service) basicAuthClient(r *http.Request) (*models.OauthClient, error) {
	// Get client credentials from basic auth
	clientID, secret, ok := r.BasicAuth()
	if !ok {
		return nil, ErrInvalidClientIDOrSecret
	}

	// Authenticate the client
	client, err := s.AuthClient(clientID, secret)
	if err != nil {
		// For security reasons, return a general error message
		return nil, ErrInvalidClientIDOrSecret
	}

	return client, nil
}
