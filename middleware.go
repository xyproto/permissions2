package userstate

// The middleware handler

import (
	"net/http"
	"strings"
)

// TODO: Find a batter place to store and manage the information for "user" and "admin" pages.

var (
	userpages  []string
	adminpages []string
)

func (state *UserState) OnlyUsers(prefix string) {
	userpages = append(userpages, prefix)
}

func (state *UserState) OnlyAdmin(prefix string) {
	adminpages = append(adminpages, prefix)
}

// Check if the user has the right admin/user rights
func (state *UserState) ServeHTTP(rw http.ResponseWriter, req *http.Request, next http.HandlerFunc) {

	path := req.URL.Path

	for _, prefix := range userpages {
		if strings.HasPrefix(path, prefix) {
			if !state.UserRights(req) {
				return // Do not call the next middleware
			}
		}
	}

	for _, prefix := range adminpages {
		if strings.HasPrefix(path, prefix) {
			if !state.AdminRights(req) {
				return // Do not call the next middleware
			}
		}
	}

	// Call the next middleware handler
	next(rw, req)
}
