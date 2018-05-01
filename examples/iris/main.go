package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/kataras/iris"
	"github.com/xyproto/permissions2"
	"github.com/xyproto/pinterface"
)

// PermissionGuard returns an new iris.Handler function that
// uses the given perm value to reject or accept HTTP requests.
// `pinterface.IPermissions` is used instead of `*permissions.Permissions`
// in order to be compatible with not only `permissions2`, but also
// other database backends, like `permissionbolt`, which uses BoltDB.
func PermissionGuard(perm pinterface.IPermissions) iris.Handler {
	return func(ctx iris.Context) {
		w := ctx.ResponseWriter()
		req := ctx.Request()
		// Check if the user has the right admin/user rights
		if perm.Rejected(w, req) {
			// Stop the request from executing further
			ctx.StopExecution()
			// Let the user know, by calling the custom "permission denied" function
			perm.DenyFunction()(w, req)
			return
		}
		// Serve the next handler if permissions were granted
		ctx.Next()
	}
}

func main() {
	app := iris.New()

	// New permissions middleware
	perm, err := permissions.New2()
	if err != nil {
		log.Fatalln(err)
	}

	// Blank slate, no default permissions
	//perm.Clear()

	// Enable the permissions middleware
	app.Use(PermissionGuard(perm))

	// Get the userstate, used in the handlers below
	userstate := perm.UserState()

	app.Get("/", func(ctx iris.Context) {
		fmt.Fprintf(ctx.ResponseWriter(), "Has user bob: %v\n", userstate.HasUser("bob"))
		fmt.Fprintf(ctx.ResponseWriter(), "Logged in on server: %v\n", userstate.IsLoggedIn("bob"))
		fmt.Fprintf(ctx.ResponseWriter(), "Is confirmed: %v\n", userstate.IsConfirmed("bob"))
		fmt.Fprintf(ctx.ResponseWriter(), "Username stored in cookies (or blank): %v\n", userstate.Username(ctx.Request()))
		fmt.Fprintf(ctx.ResponseWriter(), "Current user is logged in, has a valid cookie and *user rights*: %v\n", userstate.UserRights(ctx.Request()))
		fmt.Fprintf(ctx.ResponseWriter(), "Current user is logged in, has a valid cookie and *admin rights*: %v\n", userstate.AdminRights(ctx.Request()))
		fmt.Fprintf(ctx.ResponseWriter(), "\nTry: /register, /confirm, /remove, /login, /logout, /makeadmin, /clear, /data and /admin")
	})

	app.Get("/register", func(ctx iris.Context) {
		userstate.AddUser("bob", "hunter1", "bob@zombo.com")
		fmt.Fprintf(ctx.ResponseWriter(), "User bob was created: %v\n", userstate.HasUser("bob"))
	})

	app.Get("/confirm", func(ctx iris.Context) {
		userstate.MarkConfirmed("bob")
		fmt.Fprintf(ctx.ResponseWriter(), "User bob was confirmed: %v\n", userstate.IsConfirmed("bob"))
	})

	app.Get("/remove", func(ctx iris.Context) {
		userstate.RemoveUser("bob")
		fmt.Fprintf(ctx.ResponseWriter(), "User bob was removed: %v\n", !userstate.HasUser("bob"))
	})

	app.Get("/login", func(ctx iris.Context) {
		userstate.Login(ctx.ResponseWriter(), "bob")
		fmt.Fprintf(ctx.ResponseWriter(), "bob is now logged in: %v\n", userstate.IsLoggedIn("bob"))
	})

	app.Get("/logout", func(ctx iris.Context) {
		userstate.Logout("bob")
		fmt.Fprintf(ctx.ResponseWriter(), "bob is now logged out: %v\n", !userstate.IsLoggedIn("bob"))
	})

	app.Get("/makeadmin", func(ctx iris.Context) {
		userstate.SetAdminStatus("bob")
		fmt.Fprintf(ctx.ResponseWriter(), "bob is now administrator: %v\n", userstate.IsAdmin("bob"))
	})

	app.Get("/clear", func(ctx iris.Context) {
		userstate.ClearCookie(ctx.ResponseWriter())
		fmt.Fprintf(ctx.ResponseWriter(), "Clearing cookie")
	})

	app.Get("/data", func(ctx iris.Context) {
		fmt.Fprintf(ctx.ResponseWriter(), "Success!\n\nUser page that only logged in users must see.")
	})

	app.Get("/admin", func(ctx iris.Context) {
		fmt.Fprintf(ctx.ResponseWriter(), "Success!\n\nSuper secret information that only logged in administrators must see.\n\n")
		if usernames, err := userstate.AllUsernames(); err == nil {
			fmt.Fprintf(ctx.ResponseWriter(), "list of all users: "+strings.Join(usernames, ", "))
		}
	})

	// Custom handler for when permissions are denied
	perm.SetDenyFunction(func(w http.ResponseWriter, req *http.Request) {
		http.Error(w, "Permission denied!", http.StatusForbidden)
	})

	// Serve
	app.Run(iris.Addr(":3000"))
}
