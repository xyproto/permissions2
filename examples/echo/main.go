package main

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"log"

	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	"github.com/xyproto/permissions2"
)

func main() {
	e := echo.New()

	// New permissions middleware
	perm, err := permissions.New2()
	if err != nil {
		log.Fatalln(err)
	}

	// Blank slate, no default permissions
	//perm.Clear()

	// Set up a middleware handler for Echo, with a custom "permission denied" message.
	permissionHandler := func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			// Check if the user has the right admin/user rights
			if perm.Rejected(c.Response().Writer(), c.Request()) {
				// Deny the request
				return echo.NewHTTPError(http.StatusForbidden, "Permission denied!")
			}
			// Continue the chain of middleware
			return next(c)
		}
	}

	// Logging middleware
	e.Use(middleware.Logger())

	// Enable the permissions middleware, must come before recovery
	e.Use(permissionHandler)

	// Recovery middleware
	e.Use(middleware.Recover())

	// Get the userstate, used in the handlers below
	userstate := perm.UserState()

	e.Get("/", func(c *echo.Context) error {
		var buf bytes.Buffer
		b2s := map[bool]string{false: "false", true: "true"}
		buf.WriteString("Has user bob: " + b2s[userstate.HasUser("bob")] + "\n")
		buf.WriteString("Logged in on server: " + b2s[userstate.IsLoggedIn("bob")] + "\n")
		buf.WriteString("Is confirmed: " + b2s[userstate.IsConfirmed("bob")] + "\n")
		buf.WriteString("Username stored in cookies (or blank): " + userstate.Username(c.Request()) + "\n")
		buf.WriteString("Current user is logged in, has a valid cookie and *user rights*: " + b2s[userstate.UserRights(c.Request())] + "\n")
		buf.WriteString("Current user is logged in, has a valid cookie and *admin rights*: " + b2s[userstate.AdminRights(c.Request())] + "\n")
		buf.WriteString("\nTry: /register, /confirm, /remove, /login, /logout, /makeadmin, /clear, /data and /admin")
		return c.String(http.StatusOK, buf.String())
	})

	e.Get("/register", func(c *echo.Context) error {
		userstate.AddUser("bob", "hunter1", "bob@zombo.com")
		return c.String(http.StatusOK, fmt.Sprintf("User bob was created: %v\n", userstate.HasUser("bob")))
	})

	e.Get("/confirm", func(c *echo.Context) error {
		userstate.MarkConfirmed("bob")
		return c.String(http.StatusOK, fmt.Sprintf("User bob was confirmed: %v\n", userstate.IsConfirmed("bob")))
	})

	e.Get("/remove", func(c *echo.Context) error {
		userstate.RemoveUser("bob")
		return c.String(http.StatusOK, fmt.Sprintf("User bob was removed: %v\n", !userstate.HasUser("bob")))
	})

	e.Get("/login", func(c *echo.Context) error {
		// Headers will be written, for storing a cookie
		userstate.Login(c.Response().Writer(), "bob")
		return c.String(http.StatusOK, fmt.Sprintf("bob is now logged in: %v\n", userstate.IsLoggedIn("bob")))
	})

	e.Get("/logout", func(c *echo.Context) error {
		userstate.Logout("bob")
		return c.String(http.StatusOK, fmt.Sprintf("bob is now logged out: %v\n", !userstate.IsLoggedIn("bob")))
	})

	e.Get("/makeadmin", func(c *echo.Context) error {
		userstate.SetAdminStatus("bob")
		return c.String(http.StatusOK, fmt.Sprintf("bob is now administrator: %v\n", userstate.IsAdmin("bob")))
	})

	e.Get("/clear", func(c *echo.Context) error {
		userstate.ClearCookie(c.Response().Writer())
		return c.String(http.StatusOK, "Clearing cookie")
	})

	e.Get("/data", func(c *echo.Context) error {
		return c.String(http.StatusOK, "user page that only logged in users must see!")
	})

	e.Get("/admin", func(c *echo.Context) error {
		var buf bytes.Buffer
		buf.WriteString("super secret information that only logged in administrators must see!\n\n")
		if usernames, err := userstate.AllUsernames(); err == nil {
			buf.WriteString("list of all users: " + strings.Join(usernames, ", "))
		}
		return c.String(http.StatusOK, buf.String())
	})

	// Serve
	e.Run(":3000")
}
