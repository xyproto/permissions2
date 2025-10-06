package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/xyproto/permissions2/v2"
)

func main() {
	m := chi.NewRouter()

	// New permissions middleware
	perm, err := permissions.New2()
	if err != nil {
		log.Fatalln(err)
	}

	// Blank slate, no default permissions
	//perm.Clear()

	// Get the userstate, used in the handlers below
	userstate := perm.UserState()

	// Set up the middleware handler for Chi
	m.Use(perm.Middleware)

	m.Get("/", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "Has user bob: %t\n", userstate.HasUser("bob"))
		fmt.Fprintf(w, "Logged in on server: %t\n", userstate.IsLoggedIn("bob"))
		fmt.Fprintf(w, "Is confirmed: %t\n", userstate.IsConfirmed("bob"))
		fmt.Fprintf(w, "Username stored in cookies (or blank): %s\n", userstate.Username(req))
		fmt.Fprintf(w, "Current user is logged in, has a valid cookie and *user rights*: %t\n", userstate.UserRights(req))
		fmt.Fprintf(w, "Current user is logged in, has a valid cookie and *admin rights*: %t\n", userstate.AdminRights(req))
		fmt.Fprintf(w, "\nTry: /register, /confirm, /remove, /login, /logout, /makeadmin, /clear, /data and /admin")
	})

	m.Get("/register", func(w http.ResponseWriter, r *http.Request) {
		userstate.AddUser("bob", "hunter1", "bob@zombo.com")
		fmt.Fprintf(w, "User bob was created: %t\n", userstate.HasUser("bob"))
	})

	m.Get("/confirm", func(w http.ResponseWriter, r *http.Request) {
		userstate.MarkConfirmed("bob")
		fmt.Fprintf(w, "User bob was confirmed: %t\n", userstate.IsConfirmed("bob"))
	})

	m.Get("/remove", func(w http.ResponseWriter, r *http.Request) {
		userstate.RemoveUser("bob")
		fmt.Fprintf(w, "User bob was removed: %t\n", !userstate.HasUser("bob"))
	})

	m.Get("/login", func(w http.ResponseWriter, r *http.Request) {
		userstate.Login(w, "bob")
		fmt.Fprintf(w, "bob is now logged in: %t\n", userstate.IsLoggedIn("bob"))
	})

	m.Get("/logout", func(w http.ResponseWriter, r *http.Request) {
		userstate.Logout("bob")
		fmt.Fprintf(w, "bob is now logged out: %t\n", !userstate.IsLoggedIn("bob"))
	})

	m.Get("/makeadmin", func(w http.ResponseWriter, r *http.Request) {
		userstate.SetAdminStatus("bob")
		fmt.Fprintf(w, "bob is now administrator: %t\n", userstate.IsAdmin("bob"))
	})

	m.Get("/clear", func(w http.ResponseWriter, r *http.Request) {
		userstate.ClearCookie(w)
		fmt.Fprintf(w, "Clearing cookie")
	})

	m.Get("/data", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "user page that only logged in users must see!")
	})

	m.Get("/admin", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "super secret information that only logged in administrators must see!\n\n")
		if usernames, err := userstate.AllUsernames(); err == nil {
			fmt.Fprintf(w, "list of all users: "+strings.Join(usernames, ", "))
		}
	})

	// Custom handler for when permissions are denied
	perm.SetDenyFunction(func(w http.ResponseWriter, req *http.Request) {
		http.Error(w, "Permission denied!", http.StatusForbidden)
	})

	// Serve
	http.ListenAndServe(":3000", m)
}
