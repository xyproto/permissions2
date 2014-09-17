package permissions

import (
	"crypto/sha256"
	"errors"
	"io"
	"log"
	"math/rand"
	"net/http"
	"time"

	"github.com/xyproto/simpleredis"
)

const (
	minConfirmationCodeLength = 20   // minimum length of the confirmation code
	saltword                  = "hi" // used together with username and password when hashing
	defaultRedisServer        = ":6379"
)

type UserState struct {
	// see: http://redis.io/topics/data-types
	users        *simpleredis.HashMap        // Hash map of users, with several different fields per user ("loggedin", "confirmed", "email" etc)
	usernames    *simpleredis.Set            // A list of all usernames, for easy enumeration
	unconfirmed  *simpleredis.Set            // A list of unconfirmed usernames, for easy enumeration
	pool         *simpleredis.ConnectionPool // A connection pool for Redis
	dbindex      int                         // Redis database index
	cookieSecret string                      // Secret for storing secure cookies
	cookieTime   int64                       // How long a cookie should last, in seconds
}

// Simple way to manage user sessions, uses a pseudorandom (not random) cookie secret
func NewUserStateSimple() *UserState {
	// db index 0, initialize random generator after generating the cookie secret
	return NewUserState(0, true, defaultRedisServer)
}

// Also creates a new ConnectionPool.
// randomseed is normally true, for seeding the random number generator after generating the cookie secret
// redisHostPort can be blank, for using the local Redis instance
func NewUserState(dbindex int, randomseed bool, redisHostPort string) *UserState {
	var pool *simpleredis.ConnectionPool

	// Connnect to the default redis server if redisHostPort is empty
	if redisHostPort == "" {
		redisHostPort = defaultRedisServer
	}

	// Test connection
	if err := simpleredis.TestConnectionHost(redisHostPort); err != nil {
		log.Fatalln(err.Error())
	}
	// Aquire connection pool
	pool = simpleredis.NewConnectionPoolHost(redisHostPort)

	state := new(UserState)

	state.users = simpleredis.NewHashMap(pool, "users")
	state.users.SelectDatabase(dbindex)

	state.usernames = simpleredis.NewSet(pool, "usernames")
	state.usernames.SelectDatabase(dbindex)

	state.unconfirmed = simpleredis.NewSet(pool, "unconfirmed")
	state.unconfirmed.SelectDatabase(dbindex)

	state.pool = pool

	state.dbindex = dbindex

	// For the secure cookies
	// This must happen before the random seeding, or
	// else people will have to log in again after every server restart
	state.cookieSecret = RandomCookieFriendlyString(30)

	// Seed the random number generator
	if randomseed {
		rand.Seed(time.Now().UnixNano())
	}

	// Cookies lasts for 24 hours by default. Specified in seconds.
	state.cookieTime = defaultCookieTime

	return state
}

func (state *UserState) GetDatabaseIndex() int {
	return state.dbindex
}

func (state *UserState) GetPool() *simpleredis.ConnectionPool {
	return state.pool
}

func (state *UserState) Close() {
	state.pool.Close()
}

// Checks if the current user is logged in as a user right now
func (state *UserState) UserRights(req *http.Request) bool {
	username, err := state.GetUsernameCookie(req)
	if err != nil {
		return false
	}
	return state.IsLoggedIn(username)
}

func (state *UserState) HasUser(username string) bool {
	val, err := state.usernames.Has(username)
	if err != nil {
		// This happened at concurrent connections before introducing the connection pool
		panic("ERROR: Lost connection to Redis?")
	}
	return val
}

// Return the boolean value for a given username and fieldname.
// If the user or field is missing, false will be returned.
// Useful for states where it makes sense that the returned value is not true
// unless everything is in order.
func (state *UserState) GetBooleanField(username, fieldname string) bool {
	hasUser := state.HasUser(username)
	if !hasUser {
		return false
	}
	value, err := state.users.Get(username, fieldname)
	if err != nil {
		return false
	}
	return value == "true"
}

// Attempt to store a boolean value for the given username and fieldname.
func (state *UserState) SetBooleanField(username, fieldname string, val bool) {
	strval := "false"
	if val {
		strval = "true"
	}
	state.users.Set(username, fieldname, strval)
}

func (state *UserState) IsConfirmed(username string) bool {
	return state.GetBooleanField(username, "confirmed")
}

// Checks if the given username is logged in or not
func (state *UserState) IsLoggedIn(username string) bool {
	if !state.HasUser(username) {
		return false
	}
	status, err := state.users.Get(username, "loggedin")
	if err != nil {
		// Returns "no" if the status can not be retrieved
		return false
	}
	return status == "true"
}

// Checks if the current user is logged in as Administrator right now
func (state *UserState) AdminRights(req *http.Request) bool {
	username, err := state.GetUsernameCookie(req)
	if err != nil {
		return false
	}
	return state.IsLoggedIn(username) && state.IsAdmin(username)
}

// Checks if the given username is an administrator
func (state *UserState) IsAdmin(username string) bool {
	if !state.HasUser(username) {
		return false
	}
	status, err := state.users.Get(username, "admin")
	if err != nil {
		return false
	}
	return status == "true"
}

// Gets the username that is stored in a cookie in the browser, if available
func (state *UserState) GetUsernameCookie(req *http.Request) (string, error) {
	username, ok := GetSecureCookie(req, "user", state.cookieSecret)
	if ok && (username != "") {
		return username, nil
	}
	return "", errors.New("Could not retrieve the username from browser cookie")
}

func (state *UserState) SetUsernameCookie(w http.ResponseWriter, username string) error {
	if username == "" {
		return errors.New("Can't set cookie for empty username")
	}
	if !state.HasUser(username) {
		return errors.New("Can't store cookie for non-existsing user")
	}
	// Create a cookie that lasts for a while ("timeout" seconds),
	// this is the equivivalent of a session for a given username.
	SetSecureCookiePath(w, "user", username, state.cookieTime, "/", state.cookieSecret)
	return nil
}

func (state *UserState) GetAllUsernames() ([]string, error) {
	return state.usernames.GetAll()
}

func (state *UserState) GetEmail(username string) (string, error) {
	return state.users.Get(username, "email")
}

func (state *UserState) GetPasswordHash(username string) (string, error) {
	return state.users.Get(username, "password")
}

func (state *UserState) GetAllUnconfirmedUsernames() ([]string, error) {
	return state.unconfirmed.GetAll()
}

// Get the confirmation code for a specific user
func (state *UserState) GetConfirmationCode(username string) (string, error) {
	return state.users.Get(username, "confirmationCode")
}

func (state *UserState) GetUsers() *simpleredis.HashMap {
	return state.users
}

// Add a user that has registered but not confirmed
func (state *UserState) AddUnconfirmed(username, confirmationCode string) {
	state.unconfirmed.Add(username)
	state.users.Set(username, "confirmationCode", confirmationCode)
}

// Remove a user that has registered but not confirmed
func (state *UserState) RemoveUnconfirmed(username string) {
	state.unconfirmed.Del(username)
	state.users.DelKey(username, "confirmationCode")
}

// Mark a user as confirmed
func (state *UserState) MarkConfirmed(username string) {
	state.users.Set(username, "confirmed", "true")
}

// Remove user and login status
func (state *UserState) RemoveUser(username string) {
	state.usernames.Del(username)
	// Remove additional data as well
	state.users.DelKey(username, "loggedin")
}

// Mark user as an administrator
func (state *UserState) SetAdminStatus(username string) {
	state.users.Set(username, "admin", "true")
}

// Mark user as a regular user
func (state *UserState) RemoveAdminStatus(username string) {
	state.users.Set(username, "admin", "false")
}

// Creates a user from the username and password hash, does not check for rights
func (state *UserState) addUserUnchecked(username, passwordHash, email string) {
	// Add the user
	state.usernames.Add(username)

	// Add password and email
	state.users.Set(username, "password", passwordHash)
	state.users.Set(username, "email", email)

	// Addditional fields
	additionalfields := []string{"loggedin", "confirmed", "admin"}
	for _, fieldname := range additionalfields {
		state.users.Set(username, fieldname, "false")
	}
}

// Creates a user and hashes the password, does not check for rights.
// The given data must be valid.
func (state *UserState) AddUser(username, password, email string) {
	passwordHash := state.HashPassword(username, password)
	state.addUserUnchecked(username, passwordHash, email)
}

// Mark the user as logged in
func (state *UserState) SetLoggedIn(username string) {
	state.users.Set(username, "loggedin", "true")
}

// Mark the user as logged out
func (state *UserState) SetLoggedOut(username string) {
	state.users.Set(username, "loggedin", "false")
}

// Convenience function for logging the user in and storing the username in a cookie
func (state *UserState) Login(w http.ResponseWriter, username string) {
	state.SetLoggedIn(username)
	state.SetUsernameCookie(w, username)
}

// Convenience function for logging the user out
func (state *UserState) Logout(username string) {
	state.SetLoggedOut(username)
}

// Convenience function that will return a username or an empty string
func (state *UserState) GetUsername(req *http.Request) string {
	username, err := state.GetUsernameCookie(req)
	if err != nil {
		return ""
	}
	return username
}

// Get how long a login cookie should last, in seconds
func (state *UserState) GetCookieTimeout(username string) int64 {
	return state.cookieTime
}

// Set how long a login cookie should last, in seconds
func (state *UserState) SetCookieTimeout(cookieTime int64) {
	state.cookieTime = cookieTime
}

// Set how long a loogin cookie should last

// New password hashing function, with the username as part of the salt
func (state *UserState) HashPassword(username, password string) string {
	hasher := sha256.New()
	// Use the cookie secret as additional salt
	io.WriteString(hasher, password+state.cookieSecret+username)
	return string(hasher.Sum(nil))
}

// Check if a password is correct. username is used as part of the hash.
func (state *UserState) CorrectPassword(username, password string) bool {
	passwordHash, err := state.GetPasswordHash(username)
	if err != nil {
		return false
	}
	return passwordHash == state.HashPassword(username, password)
}

// Goes through all the confirmationCodes of all the unconfirmed users
// and checks if this confirmationCode already is in use
func (state *UserState) AlreadyHasConfirmationCode(confirmationCode string) bool {
	unconfirmedUsernames, err := state.GetAllUnconfirmedUsernames()
	if err != nil {
		return false
	}
	for _, aUsername := range unconfirmedUsernames {
		aConfirmationCode, err := state.GetConfirmationCode(aUsername)
		if err != nil {
			// If the confirmation code can not be found, that's okay too
			return false
		}
		if confirmationCode == aConfirmationCode {
			// Found it
			return true
		}
	}
	return false
}

func (state *UserState) FindUserByConfirmationCode(confirmationcode string) (string, error) {
	unconfirmedUsernames, err := state.GetAllUnconfirmedUsernames()
	if err != nil {
		return "", errors.New("All existing users are already confirmed.")
	}

	// Find the username by looking up the confirmationcode on unconfirmed users
	username := ""
	for _, aUsername := range unconfirmedUsernames {
		aConfirmationCode, err := state.GetConfirmationCode(aUsername)
		if err != nil {
			// If the confirmation code can not be found, just skip this one
			continue
		}
		if confirmationcode == aConfirmationCode {
			// Found the right user
			username = aUsername
			break
		}
	}

	// Check that the user is there
	if username == "" {
		return username, errors.New("The confirmation code is no longer valid.")
	}
	hasUser := state.HasUser(username)
	if !hasUser {
		return username, errors.New("The user that is to be confirmed no longer exists.")
	}

	return username, nil
}

// Both remove the username from the list of unconfirmed users and mark the user as confirmed
func (state *UserState) Confirm(username string) {
	// Remove from the list of unconfirmed usernames
	state.RemoveUnconfirmed(username)

	// Mark user as confirmed
	state.MarkConfirmed(username)
}

// Take a confirmation code and mark the corresponding unconfirmed user as confirmed
func (state *UserState) ConfirmUserByConfirmationCode(confirmationcode string) error {
	if username, err := state.FindUserByConfirmationCode(confirmationcode); err != nil {
		return err
	} else {
		state.Confirm(username)
	}
	return nil
}

func (state *UserState) GenerateUniqueConfirmationCode() (string, error) {
	// The confirmation code must be a minimum of 8 letters long
	length := minConfirmationCodeLength
	confirmationCode := RandomHumanFriendlyString(length)
	for state.AlreadyHasConfirmationCode(confirmationCode) {
		// Increase the length of the confirmationCode random string every time there is a collision
		length++
		confirmationCode = RandomHumanFriendlyString(length)
		if length > 100 {
			// This should never happen
			return confirmationCode, errors.New("ERROR: Too many generated confirmation codes are not unique, something is wrong")
		}
	}
	return confirmationCode, nil
}

// Check that the given username and password are different.
// Also check if the chosen letters are a-å, A-Å, 0-9 and/or _.
func ValidUsernamePassword(username, password string) error {
	const allowed_letters = "abcdefghijklmnopqrstuvwxyzæøåABCDEFGHIJKLMNOPQRSTUVWXYZÆØÅ_0123456789"
NEXT:
	for _, letter := range username {
		for _, allowedLetter := range allowed_letters {
			if letter == allowedLetter {
				continue NEXT // check the next letter in the username
			}
		}
		return errors.New("Only a-å, A-Å, 0-9 and _ are allowed in usernames.")
	}
	if username == password {
		return errors.New("Username and password must be different, try another password.")
	}
	return nil
}
