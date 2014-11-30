#Permissions [![Build Status](https://travis-ci.org/xyproto/permissions2.svg?branch=master)](https://travis-ci.org/xyproto/permissions2) [![GoDoc](https://godoc.org/github.com/xyproto/permissions2?status.svg)](http://godoc.org/github.com/xyproto/permissions2)

Middleware for [Negroni](https://github.com/codegangsta/negroni), for keeping track of users, login states and permissions.

Online API Documentation
------------------------

[godoc.org](http://godoc.org/github.com/xyproto/permissions2)


Features and limitations
------------------------

* Uses secure cookies and stores user information in a Redis database. 
* Suitable for running a local Redis server, registering/confirming users and managing public/user/admin pages.
* Also supports connecting to remote Redis servers.
* Supports registration and confirmation via generated confirmation codes.
* Tries to keep things simple.
* Only supports "public", "user" and "admin" permissions out of the box, but offers functionality for implementing more fine grained permissions, if so desired.
* Can be used together with [Martini](https://github.com/go-martini/martini), either directly or by using the [fizz](https://github.com/xyproto/fizz) package.
* Also works together with [Gin](https://github.com/gin-gonic/gin).
* May also work with other web-related packages, since the standard http.HandlerFunc is used everywhere.
* The default permissions can be cleared with the Clear() function.


Example for [Negroni](https://github.com/codegangsta/negroni)
--------------------
~~~ go
package main

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/codegangsta/negroni"
	"github.com/xyproto/permissions2"
)

func main() {
	n := negroni.Classic()
	mux := http.NewServeMux()

	// New permissions middleware
	perm := permissions.New()

	// Blank slate, no default permissions
	//perm.Clear()

	// Get the userstate, used in the handlers below
	userstate := perm.UserState()

	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "Has user bob: %v\n", userstate.HasUser("bob"))
		fmt.Fprintf(w, "Logged in on server: %v\n", userstate.IsLoggedIn("bob"))
		fmt.Fprintf(w, "Is confirmed: %v\n", userstate.IsConfirmed("bob"))
		fmt.Fprintf(w, "Username stored in cookies (or blank): %v\n", userstate.Username(req))
		fmt.Fprintf(w, "Current user is logged in, has a valid cookie and *user rights*: %v\n", userstate.UserRights(req))
		fmt.Fprintf(w, "Current user is logged in, has a valid cookie and *admin rights*: %v\n", userstate.AdminRights(req))
		fmt.Fprintf(w, "\nTry: /register, /confirm, /remove, /login, /logout, /data, /makeadmin and /admin")
	})

	mux.HandleFunc("/register", func(w http.ResponseWriter, req *http.Request) {
		userstate.AddUser("bob", "hunter1", "bob@zombo.com")
		fmt.Fprintf(w, "User bob was created: %v\n", userstate.HasUser("bob"))
	})

	mux.HandleFunc("/confirm", func(w http.ResponseWriter, req *http.Request) {
		userstate.MarkConfirmed("bob")
		fmt.Fprintf(w, "User bob was confirmed: %v\n", userstate.IsConfirmed("bob"))
	})

	mux.HandleFunc("/remove", func(w http.ResponseWriter, req *http.Request) {
		userstate.RemoveUser("bob")
		fmt.Fprintf(w, "User bob was removed: %v\n", !userstate.HasUser("bob"))
	})

	mux.HandleFunc("/login", func(w http.ResponseWriter, req *http.Request) {
		userstate.Login(w, "bob")
		fmt.Fprintf(w, "bob is now logged in: %v\n", userstate.IsLoggedIn("bob"))
	})

	mux.HandleFunc("/logout", func(w http.ResponseWriter, req *http.Request) {
		userstate.Logout("bob")
		fmt.Fprintf(w, "bob is now logged out: %v\n", !userstate.IsLoggedIn("bob"))
	})

	mux.HandleFunc("/makeadmin", func(w http.ResponseWriter, req *http.Request) {
		userstate.SetAdminStatus("bob")
		fmt.Fprintf(w, "bob is now administrator: %v\n", userstate.IsAdmin("bob"))
	})

	mux.HandleFunc("/data", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "user page that only logged in users must see!")
	})

	mux.HandleFunc("/admin", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "super secret information that only logged in administrators must see!\n\n")
		if usernames, err := userstate.AllUsernames(); err == nil {
			fmt.Fprintf(w, "list of all users: "+strings.Join(usernames, ", "))
		}
	})

	// Custom handler for when permissions are denied
	perm.SetDenyFunction(func(w http.ResponseWriter, req *http.Request) {
		http.Error(w, "Permission denied!", http.StatusForbidden)
	})

	// Enable the permissions middleware
	n.Use(perm)

	// Use mux for routing, this goes last
	n.UseHandler(mux)

	// Serve
	n.Run(":3000")
}
~~~

Example for [Martini](https://github.com/go-martini/martini)
--------------------
~~~ go
package main

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/go-martini/martini"
	"github.com/xyproto/permissions2"
)

func main() {
	m := martini.Classic()

	// New permissions middleware
	perm := permissions.New()

	// Blank slate, no default permissions
	//perm.Clear()

	// Get the userstate, used in the handlers below
	userstate := perm.UserState()

	m.Get("/", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "Has user bob: %v\n", userstate.HasUser("bob"))
		fmt.Fprintf(w, "Logged in on server: %v\n", userstate.IsLoggedIn("bob"))
		fmt.Fprintf(w, "Is confirmed: %v\n", userstate.IsConfirmed("bob"))
		fmt.Fprintf(w, "Username stored in cookies (or blank): %v\n", userstate.Username(req))
		fmt.Fprintf(w, "Current user is logged in, has a valid cookie and *user rights*: %v\n", userstate.UserRights(req))
		fmt.Fprintf(w, "Current user is logged in, has a valid cookie and *admin rights*: %v\n", userstate.AdminRights(req))
		fmt.Fprintf(w, "\nTry: /register, /confirm, /remove, /login, /logout, /data, /makeadmin and /admin")
	})

	m.Get("/register", func(w http.ResponseWriter, req *http.Request) {
		userstate.AddUser("bob", "hunter1", "bob@zombo.com")
		fmt.Fprintf(w, "User bob was created: %v\n", userstate.HasUser("bob"))
	})

	m.Get("/confirm", func(w http.ResponseWriter, req *http.Request) {
		userstate.MarkConfirmed("bob")
		fmt.Fprintf(w, "User bob was confirmed: %v\n", userstate.IsConfirmed("bob"))
	})

	m.Get("/remove", func(w http.ResponseWriter, req *http.Request) {
		userstate.RemoveUser("bob")
		fmt.Fprintf(w, "User bob was removed: %v\n", !userstate.HasUser("bob"))
	})

	m.Get("/login", func(w http.ResponseWriter, req *http.Request) {
		userstate.Login(w, "bob")
		fmt.Fprintf(w, "bob is now logged in: %v\n", userstate.IsLoggedIn("bob"))
	})

	m.Get("/logout", func(w http.ResponseWriter, req *http.Request) {
		userstate.Logout("bob")
		fmt.Fprintf(w, "bob is now logged out: %v\n", !userstate.IsLoggedIn("bob"))
	})

	m.Get("/makeadmin", func(w http.ResponseWriter, req *http.Request) {
		userstate.SetAdminStatus("bob")
		fmt.Fprintf(w, "bob is now administrator: %v\n", userstate.IsAdmin("bob"))
	})

	m.Get("/data", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "user page that only logged in users must see!")
	})

	m.Get("/admin", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "super secret information that only logged in administrators must see!\n\n")
		if usernames, err := userstate.AllUsernames(); err == nil {
			fmt.Fprintf(w, "list of all users: "+strings.Join(usernames, ", "))
		}
	})

	// Set up a middleware handler for Martini, with a custom "permission denied" message.
	// Use the xyproto/fizz middleware for a simpler solution.
	permissionHandler := func(w http.ResponseWriter, req *http.Request, c martini.Context) {
		// Check if the user has the right admin/user rights
		if perm.Rejected(w, req) {
			// Deny the request
			http.Error(w, "Permission denied!", http.StatusForbidden)
			// Reject the request by not calling the next handler below
			return
		}
		// Call the next middleware handler
		c.Next()
	}

	// Enable the permissions middleware
	m.Use(permissionHandler)

	// Serve
	m.Run()
}
~~~


Default permissions
-------------------

* The */admin* path prefix has admin rights by default.
* These path prefixes has user rights by default: */repo* and */data*
* These path prefixes are public by default: */*, */login*, */register*, */style*, */img*, */js*, */favicon.ico*, */robots.txt* and */sitemap_index.xml*


Password hashing
----------------

* "bcrypt" is used by default for hashing passwords. "sha256" is also supported.
* By default, all new password will be hashed with "bcrypt". Old password hashes will be checked with both sha256 and bcrypt, for backwards compatibility. Only old hashes with the length of a sha256 hash will be checked with sha256. To disable this behavior, and only ever use bcrypt, set the password hashing algorithm to "bcrypt". Example: `userstate.SetPasswordAlgo("bcrypt")`

Coding style
------------

* log.Fatal or panic should only be used for problems that may occur when starting the application, like not being able to connect to the database. The rest of the functions should return errors instead, so that they can be handled.
* The code should always be formatted with `go fmt`.

General information
-------------------

* Version: 2.0
* License: MIT
* Alexander F Rødseth

