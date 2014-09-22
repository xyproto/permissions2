#Permissions [![Build Status](https://travis-ci.org/xyproto/permissions.svg?branch=master)](https://travis-ci.org/xyproto/permissions) [![GoDoc](https://godoc.org/github.com/xyproto/permissions?status.svg)](http://godoc.org/github.com/xyproto/permissions)
<!--[![Build Status](https://drone.io/github.com/xyproto/permissions/status.png)](https://drone.io/github.com/xyproto/permissions/latest)    build succeeds, but github says build fails. Weirdness. -->

Middleware for Negroni, for keeping track of users, login states and permissions.


Online API Documentation
------------------------

[godoc.org](http://godoc.org/github.com/xyproto/permissions)


Features and limitations
------------------------

* Uses secure cookies and stores user information in a Redis database. 
* Suitable for running a local Redis server, registering/confirming users and managing public/user/admin pages.
* Supports registration and confirmation via generated confirmation codes.
* Tries to keep things simple.
* Only supports "public", "user" and "admin" permissions out of the box, but offers functionality for implementing more fine grained permissions, if so desired.


Example for [Negroni](https://github.com/codegangsta/negroni)
--------------------
~~~ go
package main

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/codegangsta/negroni"
	"github.com/xyproto/permissions"
)

func main() {
	n := negroni.Classic()

	perm := permissions.New()
	userstate := perm.UserState()

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "Has user bob: %v\n", userstate.HasUser("bob"))
		fmt.Fprintf(w, "Logged in on server: %v\n", userstate.IsLoggedIn("bob"))
		fmt.Fprintf(w, "Is confirmed: %v\n", userstate.IsConfirmed("bob"))
		fmt.Fprintf(w, "Username stored in cookies (or blank): %v\n", userstate.GetUsername(req))
		fmt.Fprintf(w, "Current user is logged in, has a valid cookie and *user rights*: %v\n", userstate.UserRights(req))
		fmt.Fprintf(w, "Current user is logged in, has a valid cookie and *admin rights*: %v\n", userstate.AdminRights(req))
		fmt.Fprintf(w, "\nTry: /register, /confirm, /remove, /login, /logout, /makeadmin and /admin")
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
		if usernames, err := userstate.GetAllUsernames(); err == nil {
			fmt.Fprintf(w, "list of all users: "+strings.Join(usernames, ", "))
		}
	})

	perm.SetDenyFunction(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Permission denied!")
	})

	n.Use(perm)

	n.UseHandler(mux)

	n.Run(":3000")
}
~~~

Default permissions
-------------------

* The */admin* path prefix has admin rights by default.
* These path prefixes has user rights by default: */repo* and */data*
* These path prefixes are public by default: */*, */login*, */register*, */style*, */img*, */js*, */favicon.ico*, */robots.txt* and */sitemap_index.xml*

General information
-------------------

* Version: 1.0
* License: MIT
* Alexander F Rødseth

