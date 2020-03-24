package oauth

import (
	"github.com/RichardKnop/go-oauth2-server/util/routes"
	"github.com/gorilla/mux"
	"net/http"
)

const (
	tokensResource     = "tokens"
	tokensPath         = "/" + tokensResource
	introspectResource = "introspect"
	introspectPath     = "/" + introspectResource
)

// RegisterRoutes registers route handlers for the oauth service
func (s *Service) RegisterRoutes(router *mux.Router, prefix string) {
	subRouter := router.PathPrefix(prefix).Subrouter()
	routes.AddRoutes(s.GetRoutes(), subRouter)
}

// corsPreFlightHandler ...
func corsPreFlightHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
	return
}

// GetRoutes returns []routes.Route slice for the oauth service
func (s *Service) GetRoutes() []routes.Route {
	return []routes.Route{
		{
			Name:        "oauth_tokens",
			Method:      "POST",
			Pattern:     tokensPath,
			HandlerFunc: s.tokensHandler,
		},
		{
			Name:        "oauth_tokens",
			Method:      "OPTIONS",
			Pattern:     tokensPath,
			HandlerFunc: corsPreFlightHandler,
		},
		{
			Name:        "oauth_introspect",
			Method:      "POST",
			Pattern:     introspectPath,
			HandlerFunc: s.introspectHandler,
		},
		{
			Name:        "oauth_introspect",
			Method:      "OPTIONS",
			Pattern:     introspectPath,
			HandlerFunc: corsPreFlightHandler,
		},
	}
}
