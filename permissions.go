package userstate

// The middleware handler

import (
	"net/http"
	"strings"
)

// TODO: Find a batter place to store and manage the information for "user" and "admin" pages.

var perm Permissions

type Permissions struct {
	state *UserState
	adminpages  []string
	userpages  []string
	publicpages []string
}

func New() *Permissions {
	return NewPermissions(NewUserState(0, true))
}

func NewPermissions(state *UserState) *Permissions {
	return &Permissions{state, []string{"/admin"}, []string{"/"}, []string{"/"}}
}

func (perm *Permissions) UserState() *UserState {
	return perm.state
}

func (perm *Permissions) AllowUsers(prefix string) {
	perm.userpages = append(perm.userpages, prefix)
}

func (perm *Permissions) AllowPublic(prefix string) {
	perm.publicpages = append(perm.publicpages, prefix)
}

// Check if the user has the right admin/user rights
func (perm *Permissions) ServeHTTP(rw http.ResponseWriter, req *http.Request, next http.HandlerFunc) {

	path := req.URL.Path // the path of the url that the user wish to visit
	allow := false       // anyone but administartors have access?

	// Allow if it is a public page
	for _, prefix := range perm.publicpages {
		if strings.HasPrefix(path, prefix) {
			allow = true
			break
		}
	}

	if !allow {
		// Allow if the user has user rights and it's a user page
		for _, prefix := range perm.userpages {
			if strings.HasPrefix(path, prefix) {
				if perm.state.UserRights(req) {
					allow = true
					break
				}
			}
		}
	}

	// Allow if the user has administrator rights
	if !allow && perm.state.AdminRights(req) {
		allow = true
	}

	if allow {
		// Call the next middleware handler
		next(rw, req)
	} // else, deny access, don't call the next middleware
}
