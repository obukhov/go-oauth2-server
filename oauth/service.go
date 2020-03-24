package oauth

import (
	"encoding/json"
	"errors"
	"github.com/RichardKnop/go-oauth2-server/config"
	"github.com/RichardKnop/go-oauth2-server/oauth/roles"
	"github.com/jinzhu/gorm"
	"net/http"
)

var (
	// ErrMissingContentType ...
	ErrMissingContentType = errors.New("Missing content type")
)

// Service struct keeps objects to avoid passing them around
type Service struct {
	cnf          *config.Config
	db           *gorm.DB
	allowedRoles []string
}

// NewService returns a new Service instance
func NewService(cnf *config.Config, db *gorm.DB) *Service {
	return &Service{
		cnf:          cnf,
		db:           db,
		allowedRoles: []string{roles.Superuser, roles.User},
	}
}

// GetConfig returns config.Config instance
func (s *Service) GetConfig() *config.Config {
	return s.cnf
}

// RestrictToRoles restricts this service to only specified roles
func (s *Service) RestrictToRoles(allowedRoles ...string) {
	s.allowedRoles = allowedRoles
}

// IsRoleAllowed returns true if the role is allowed to use this service
func (s *Service) IsRoleAllowed(role string) bool {
	for _, allowedRole := range s.allowedRoles {
		if role == allowedRole {
			return true
		}
	}
	return false
}

// DecodeRequest ...
func (s *Service) DecodeRequest(r *http.Request, target interface{}) error {
	var contentType string

	if len(r.Header["Content-Type"]) < 1 {
		return ErrMissingContentType
	}

	contentType = r.Header["Content-Type"][0]

	if len(contentType) <= 0 {
		return ErrMissingContentType
	}

	if contentType == "application/json" {
		dec := json.NewDecoder(r.Body)
		//dec.DisallowUnknownFields()
		return dec.Decode(target)
	} else if contentType == "application/x-www-form-urlencoded" {
		// Parse the form so r.Form becomes available
		err := r.ParseForm()
		if err != nil {
			return err
		}

		err = decoder.Decode(target, r.PostForm)
		if err != nil {
			return err
		}
	}

	return nil
}

// Close stops any running services
func (s *Service) Close() {}
