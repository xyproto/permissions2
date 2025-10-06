// Package permissions provides a way to keep track of users, login states and permissions.
package permissions

import (
	"net/http"
	"strings"

	"github.com/xyproto/pinterface"
)

const (
	// Version number. Stable API within major version numbers.
	Version = 2.6
)

// Permissions is a structure that keeps track of the permissions for various path prefixes
type Permissions struct {
	state              *UserState
	adminPathPrefixes  []string
	userPathPrefixes   []string
	publicPathPrefixes []string
	rootIsPublic       bool
	denied             http.HandlerFunc
}

// New will initialize a Permissions struct with all the default settings.
// This will also connect to the redis host at localhost:6379.
func New() *Permissions {
	return NewPermissions(NewUserStateSimple())
}

// New2 will initialize a Permissions struct with all the default settings.
// This will also connect to the redis host at localhost:6379.
func New2() (*Permissions, error) {
	userstate, err := NewUserStateSimple2()
	if err != nil {
		return nil, err
	}
	return NewPermissions(userstate), nil
}

// NewWithRedisConf will initialize a Permissions struct with Redis DB index and host:port.
// Calls log.Fatal if something goes wrong.
func NewWithRedisConf(dbindex int, hostPort string) *Permissions {
	return NewPermissions(NewUserState(dbindex, true, hostPort))
}

// NewWithRedisConf2 will initialize a Permissions struct with Redis DB index and host:port.
// Returns an error if something goes wrong.
func NewWithRedisConf2(dbindex int, hostPort string) (*Permissions, error) {
	userstate, err := NewUserState2(dbindex, true, hostPort)
	if err != nil {
		return nil, err
	}
	return NewPermissions(userstate), nil
}

// NewPermissions will initialize a Permissions struct with the given UserState and
// a few default paths for admin/user/public path prefixes.
func NewPermissions(state *UserState) *Permissions {
	// default permissions
	return &Permissions{state,
		[]string{"/admin"},         // admin path prefixes
		[]string{"/repo", "/data"}, // user path prefixes
		[]string{"/",
			"/login",
			"/register",
			"/favicon.ico",
			"/style",
			"/img",
			"/js",
			"/favicon.ico",
			"/robots.txt",
			"/sitemap_index.xml"}, // public
		true,
		PermissionDenied}
}

// SetDenyFunction can be used for specifying a http.HandlerFunc that will be used when the permissions are denied.
func (perm *Permissions) SetDenyFunction(f http.HandlerFunc) {
	perm.denied = f
}

// DenyFunction returns the current http.HandlerFunc, for when permissions are denied.
func (perm *Permissions) DenyFunction() http.HandlerFunc {
	return perm.denied
}

// UserState retrieves the UserState struct
func (perm *Permissions) UserState() pinterface.IUserState {
	return perm.state
}

// Clear sets every URL path prefix permission to "public"
func (perm *Permissions) Clear() {
	perm.adminPathPrefixes = []string{}
	perm.userPathPrefixes = []string{}
}

// AddAdminPath registers a path prefix for URLs that shall only be reached by logged in administrators
func (perm *Permissions) AddAdminPath(prefix string) {
	perm.adminPathPrefixes = append(perm.adminPathPrefixes, prefix)
}

// AddUserPath registers a path prefix for URLs that shall only be reached by logged in users
func (perm *Permissions) AddUserPath(prefix string) {
	perm.userPathPrefixes = append(perm.userPathPrefixes, prefix)
}

// AddPublicPath registers a path prefix for URLs that can be reached by anyone
func (perm *Permissions) AddPublicPath(prefix string) {
	perm.publicPathPrefixes = append(perm.publicPathPrefixes, prefix)
}

// SetAdminPath can be used for setting all URL path prefixes that are for the logged in administrator pages.
func (perm *Permissions) SetAdminPath(pathPrefixes []string) {
	perm.adminPathPrefixes = pathPrefixes
}

// SetUserPath can be used for setting all URL path prefixes that are for the logged in user pages.
func (perm *Permissions) SetUserPath(pathPrefixes []string) {
	perm.userPathPrefixes = pathPrefixes
}

// SetPublicPath can be used for setting all URL path prefixes that are for the public pages.
func (perm *Permissions) SetPublicPath(pathPrefixes []string) {
	perm.publicPathPrefixes = pathPrefixes
}

// PermissionDenied is the default "permission denied" http handler.
func PermissionDenied(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "Permission denied.", http.StatusForbidden)
}

// Rejected checks if a given request should be rejected.
func (perm *Permissions) Rejected(_ http.ResponseWriter, req *http.Request) bool {
	path := req.URL.Path // the path of the url that the user wish to visit

	// If it's not "/" and set to be public regardless of permissions
	if perm.rootIsPublic && path == "/" {
		return false
	}

	// Reject if it is an admin page and user does not have admin permissions
	for _, prefix := range perm.adminPathPrefixes {
		if strings.HasPrefix(path, prefix) {
			if !perm.state.AdminRights(req) {
				// Reject
				return true
			}
		}
	}

	// Reject if it's a user page and the user does not have user rights
	for _, prefix := range perm.userPathPrefixes {
		if strings.HasPrefix(path, prefix) {
			if !perm.state.UserRights(req) {
				// Reject
				return true
			}
		}
	}

	// Don't reject if it's a public page
	for _, prefix := range perm.publicPathPrefixes {
		if strings.HasPrefix(path, prefix) {
			// Don't reject
			return false
		}
	}

	// Reject
	return true
}

// Middleware handler (compatible with Negroni)
func (perm *Permissions) ServeHTTP(w http.ResponseWriter, req *http.Request, next http.HandlerFunc) {
	// Check if the user has the right admin/user rights
	if perm.Rejected(w, req) {
		// Get and call the Permission Denied function
		perm.DenyFunction()(w, req)
		// Reject the request by not calling the next handler below
		return
	}
	// Call the next middleware handler
	next(w, req)
}

// Middleware handler (compatible with Chi)
func (perm *Permissions) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Check if the user has the right admin/user rights
		if perm.Rejected(w, req) {
			// Get and call the Permission Denied function
			perm.DenyFunction()(w, req)
			// Reject the request by not calling the next handler below
			return
		}
		// Call the next middleware handler
		next.ServeHTTP(w, req)
	})
}
