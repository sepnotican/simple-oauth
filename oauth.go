package simple_oauth

import (
	"fmt"
	"sync"
)

type ServiceProvider interface {
	OAuthLogin() (oauthState string, url string, err error)
	OAuthCallback(stateCookie, stateForm, code string) (UserDataSupplier, error)
}

type UserDataSupplier interface {
	GetEmail() string
	GetFirstName() string
	GetLastName() string
	GetAvatarURL() string
}

type Handler struct {
	mx *sync.RWMutex

	providers map[string]ServiceProvider
}

func New() *Handler {
	return &Handler{
		mx:        &sync.RWMutex{},
		providers: map[string]ServiceProvider{},
	}
}

func (h Handler) AddProvider(name string, p ServiceProvider) {
	h.mx.Lock()
	defer h.mx.Unlock()
	h.providers[name] = p
}

func (h Handler) OAuthLogin(providerName string) (oauthState string, url string, err error) {
	h.mx.RLock()
	defer h.mx.RUnlock()
	p, ok := h.providers[providerName]
	if !ok {
		return "", "", fmt.Errorf("provider %s not found", providerName)
	}
	return p.OAuthLogin()
}

func (h Handler) OAuthCallback(providerName string, stateCookie, stateForm, code string) (UserDataSupplier, error) {
	h.mx.RLock()
	defer h.mx.RUnlock()
	p, ok := h.providers[providerName]
	if !ok {
		return nil, fmt.Errorf("provider %s not found", providerName)
	}
	return p.OAuthCallback(stateCookie, stateForm, code)
}
