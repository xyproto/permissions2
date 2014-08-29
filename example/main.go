package main

import (
	"fmt"
	"net/http"

	"github.com/codegangsta/negroni"
	"github.com/xyproto/userstate"
)

func main() {
	n := negroni.Classic()

	permissions := userstate.New()
	u := permissions.UserState()

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "Has user bob: %v\nLogged in: %v\n", u.HasUser("bob"), u.IsLoggedIn("bob"))
		fmt.Fprintf(w, "Is confirmed: %v\n", u.IsConfirmed("bob"))
		fmt.Fprintf(w, "Current user is logged in and has user rights: %v\n", u.UserRights(req))
		fmt.Fprintf(w, "Current user is logged in and has admin rights: %v\n", u.AdminRights(req))
		fmt.Fprintf(w, "Username stored in cookies (or blank): %v\n", u.GetUsername(req))
		fmt.Fprintf(w, "\nTry: /register, /confirm, /remove, /login, /logout and /admin")
	})

	mux.HandleFunc("/register", func(w http.ResponseWriter, req *http.Request) {
		u.AddUser("bob", "hunter1", "bob@zombo.com")
		fmt.Fprintf(w, "User bob was created: %v\n", u.HasUser("bob"))
	})

	mux.HandleFunc("/confirmationcode", func(w http.ResponseWriter, req *http.Request) {
		u.MarkConfirmed("bob")
		fmt.Fprintf(w, "User bob was confirmed: %v\n", u.IsConfirmed("bob"))
	})

	mux.HandleFunc("/confirm", func(w http.ResponseWriter, req *http.Request) {
		u.MarkConfirmed("bob")
		fmt.Fprintf(w, "User bob was confirmed: %v\n", u.IsConfirmed("bob"))
	})

	mux.HandleFunc("/remove", func(w http.ResponseWriter, req *http.Request) {
		u.RemoveUser("bob")
		fmt.Fprintf(w, "User bob was removed: %v\n", !u.HasUser("bob"))
	})

	mux.HandleFunc("/login", func(w http.ResponseWriter, req *http.Request) {
		u.Login(w, "bob")
		fmt.Fprintf(w, "bob is now logged in: %v\n", u.IsLoggedIn("bob"))
	})

	mux.HandleFunc("/logout", func(w http.ResponseWriter, req *http.Request) {
		u.Logout("bob")
		fmt.Fprintf(w, "bob is now logged out: %v\n", !u.IsLoggedIn("bob"))
	})

	mux.HandleFunc("/makeadmin", func(w http.ResponseWriter, req *http.Request) {
		u.SetAdminStatus("bob")
		fmt.Fprintf(w, "bob is now administrator: %v\n", u.IsAdmin("bob"))
	})

	mux.HandleFunc("/user", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "user page that only users must see!")
	})

	mux.HandleFunc("/admin", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "super secret information that only administrators must see!")
	})

	n.Use(permissions)

	n.UseHandler(mux)

	n.Run(":3000")
}
