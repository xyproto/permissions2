package permissions

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"time"

	"code.google.com/p/go.crypto/bcrypt"
	"github.com/xyproto/simpleredis"
)

const (
	defaultRedisServer = ":6379"
)

var (
	minConfirmationCodeLength = 20 // minimum length of the confirmation code
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
	passwordAlgo string                      // The hashing algorithm to utilize default: "bcrypt+" allowed: ("sha256", "bcrypt", "bcrypt+")
}

// Huge interface for making it possible to depend on different versions of the permission package
type UserStateKeeper interface {
	DatabaseIndex() int
	Pool() *simpleredis.ConnectionPool
	Close()
	UserRights(req *http.Request) bool
	HasUser(username string) bool
	BooleanField(username, fieldname string) bool
	SetBooleanField(username, fieldname string, val bool)
	IsConfirmed(username string) bool
	IsLoggedIn(username string) bool
	AdminRights(req *http.Request) bool
	IsAdmin(username string) bool
	UsernameCookie(req *http.Request) (string, error)
	SetUsernameCookie(w http.ResponseWriter, username string) error
	AllUsernames() ([]string, error)
	Email(username string) (string, error)
	PasswordHash(username string) (string, error)
	AllUnconfirmedUsernames() ([]string, error)
	ConfirmationCode(username string) (string, error)
	Users() *simpleredis.HashMap
	AddUnconfirmed(username, confirmationCode string)
	RemoveUnconfirmed(username string)
	MarkConfirmed(username string)
	RemoveUser(username string)
	SetAdminStatus(username string)
	RemoveAdminStatus(username string)
	addUserUnchecked(username, passwordHash, email string)
	AddUser(username, password, email string)
	SetLoggedIn(username string)
	SetLoggedOut(username string)
	Login(w http.ResponseWriter, username string)
	Logout(username string)
	Username(req *http.Request) string
	CookieTimeout(username string) int64
	SetCookieTimeout(cookieTime int64)
	PasswordAlgo() string
	SetPasswordAlgo(algo string)
	HashPassword(username, password string) string
	CorrectPassword(username, password string) bool
	AlreadyHasConfirmationCode(confirmationCode string) bool
	FindUserByConfirmationCode(confirmationcode string) (string, error)
	Confirm(username string)
	ConfirmUserByConfirmationCode(confirmationcode string) error
	SetMinimumConfirmationCodeLength(length int)
	GenerateUniqueConfirmationCode() (string, error)
}

// Create a new *UserState that can be used for managing users.
// The random number generator will be seeded after generating the cookie secret.
// A connection pool for the local Redis server (dbindex 0) will be created.
func NewUserStateSimple() *UserState {
	// db index 0, initialize random generator after generating the cookie secret
	return NewUserState(0, true, defaultRedisServer)
}

// Create a new *UserState that can be used for managing users.
// dbindex is the Redis database index.
// If randomseed is true, the random number generator will be seeded after generating the cookie secret.
// redisHostPort is host:port for the desired Redis server (can be blank for localhost)
// Also creates a new ConnectionPool.
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

	// Default password algorithm is "bcrypt+", which is the same as "bcrypt",
	// but with backwards compatibility for checking sha256 hashes.
	state.passwordAlgo = "bcrypt+" // "bcrypt+", "bcrypt" or "sha256"

	return state
}

// Get the Redis database index
func (state *UserState) DatabaseIndex() int {
	return state.dbindex
}

// Get the Redis connection pool
func (state *UserState) Pool() *simpleredis.ConnectionPool {
	return state.pool
}

// Close the Redis connection pool
func (state *UserState) Close() {
	state.pool.Close()
}

// Check if the current user is logged in as a user right now
func (state *UserState) UserRights(req *http.Request) bool {
	username, err := state.UsernameCookie(req)
	if err != nil {
		return false
	}
	return state.IsLoggedIn(username)
}

// Check if the given username exists
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
func (state *UserState) BooleanField(username, fieldname string) bool {
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

// Check if the given username is confirmed
func (state *UserState) IsConfirmed(username string) bool {
	return state.BooleanField(username, "confirmed")
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

// Check if the current user is logged in as Administrator right now
func (state *UserState) AdminRights(req *http.Request) bool {
	username, err := state.UsernameCookie(req)
	if err != nil {
		return false
	}
	return state.IsLoggedIn(username) && state.IsAdmin(username)
}

// Check if the given username is an administrator
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

// Retrieve the username that is stored in a cookie in the browser, if available
func (state *UserState) UsernameCookie(req *http.Request) (string, error) {
	username, ok := SecureCookie(req, "user", state.cookieSecret)
	if ok && (username != "") {
		return username, nil
	}
	return "", errors.New("Could not retrieve the username from browser cookie")
}

// Store the given username in a cookie in the browser, if possible.
// The user must exist.
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

// Get a list of all usernames
func (state *UserState) AllUsernames() ([]string, error) {
	return state.usernames.GetAll()
}

// Get the email for the given username
func (state *UserState) Email(username string) (string, error) {
	return state.users.Get(username, "email")
}

// Get the password hash for the given username
func (state *UserState) PasswordHash(username string) (string, error) {
	return state.users.Get(username, "password")
}

// Get all registered users that are not yet confirmed
func (state *UserState) AllUnconfirmedUsernames() ([]string, error) {
	return state.unconfirmed.GetAll()
}

// Get the confirmation code for a specific user
func (state *UserState) ConfirmationCode(username string) (string, error) {
	return state.users.Get(username, "confirmationCode")
}

// Get the users HashMap
func (state *UserState) Users() *simpleredis.HashMap {
	return state.users
}

// Add a user that is registered but not confirmed
func (state *UserState) AddUnconfirmed(username, confirmationCode string) {
	state.unconfirmed.Add(username)
	state.users.Set(username, "confirmationCode", confirmationCode)
}

// Remove a user that is registered but not confirmed
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

// Mark the user as logged in. Use the Login function instead, unless cookies are not involved.
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

// Convenience function that will return a username (from the browser cookie) or an empty string
func (state *UserState) Username(req *http.Request) string {
	username, err := state.UsernameCookie(req)
	if err != nil {
		return ""
	}
	return username
}

// Get how long a login cookie should last, in seconds
func (state *UserState) CookieTimeout(username string) int64 {
	return state.cookieTime
}

// Set how long a login cookie should last, in seconds
func (state *UserState) SetCookieTimeout(cookieTime int64) {
	state.cookieTime = cookieTime
}

// Get current password algorithm
func (state *UserState) PasswordAlgo() string {
	return state.passwordAlgo
}

// Set the password hashing algorithm that should be used
func (state *UserState) SetPasswordAlgo(algo string) {
	// If algo is "bcrypt+", bcrypt will be used when hashing and previously
	// stored bcrypt and sha256 hashes will be tested when comparing.
	switch algo {
	case "sha256", "bcrypt", "bcrypt+":
		state.passwordAlgo = algo
	default:
		panic(fmt.Sprintf("Permissions: '%v' is an unsupported encryption algorithm", algo))
	}
}

// Hash the password
// if using sha256, use the cookieSecret and username as part of the salt
// if using bcrypt, rely on it for salting
func (state *UserState) HashPassword(username, password string) string {
	switch state.passwordAlgo {
	case "sha256":
		hasher := sha256.New()
		// Use the cookie secret as additional salt
		io.WriteString(hasher, password+state.cookieSecret+username)
		return string(hasher.Sum(nil))
	case "bcrypt", "bcrypt+":
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			panic("Permissions: bcrypt password hashing unsuccessful")
		}
		return string(hash)
	default:
		panic(fmt.Sprintf("Permissions: '%v' is an unsupported encryption algorithm", state.passwordAlgo))
	}
}

// Check if a given password(+username) is correct, for a given sha256 hash
func (state *UserState) correct_sha256(hash, username, password string) bool {
	// prevents timing attack
	return subtle.ConstantTimeCompare([]byte(hash), []byte(state.HashPassword(username, password))) == 1
}

// Check if a given password is correct, for a given bcrypt hash
func correct_bcrypt(hash, password string) bool {
	// prevents timing attack
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// Check if a password is correct. username is needed because it is part of the hash.
func (state *UserState) CorrectPassword(username, password string) bool {

	if !state.HasUser(username) {
		return false
	}

	hash, err := state.PasswordHash(username)
	if err != nil {
		return false
	}

	switch state.passwordAlgo {
	case "sha256":
		return state.correct_sha256(hash, username, password)
	case "bcrypt":
		return correct_bcrypt(hash, password)
	case "bcrypt+": // for backwards compatibility with sha256
		if len(hash) == 32 {
			return state.correct_sha256(hash, username, password)
		} else {
			return correct_bcrypt(hash, password)
		}
	}

	return false
}

// Goes through all the confirmationCodes of all the unconfirmed users
// and checks if this confirmationCode already is in use
func (state *UserState) AlreadyHasConfirmationCode(confirmationCode string) bool {
	unconfirmedUsernames, err := state.AllUnconfirmedUsernames()
	if err != nil {
		return false
	}
	for _, aUsername := range unconfirmedUsernames {
		aConfirmationCode, err := state.ConfirmationCode(aUsername)
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

// Given a unique confirmation code, find the corresponding username
func (state *UserState) FindUserByConfirmationCode(confirmationcode string) (string, error) {
	unconfirmedUsernames, err := state.AllUnconfirmedUsernames()
	if err != nil {
		return "", errors.New("All existing users are already confirmed.")
	}

	// Find the username by looking up the confirmationcode on unconfirmed users
	username := ""
	for _, aUsername := range unconfirmedUsernames {
		aConfirmationCode, err := state.ConfirmationCode(aUsername)
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

// Set the minimum length of the user confirmation code. The default is 20.
func (state *UserState) SetMinimumConfirmationCodeLength(length int) {
	minConfirmationCodeLength = length
}

// Generate a unique confirmation code that can be used for confirming users
func (state *UserState) GenerateUniqueConfirmationCode() (string, error) {
	const maxConfirmationCodeLength = 100 // when are the generated confirmation codes unreasonably long
	length := minConfirmationCodeLength
	confirmationCode := RandomHumanFriendlyString(length)
	for state.AlreadyHasConfirmationCode(confirmationCode) {
		// Increase the length of the confirmationCode random string every time there is a collision
		length++
		confirmationCode = RandomHumanFriendlyString(length)
		if length > maxConfirmationCodeLength {
			// This should never happen
			return confirmationCode, errors.New("Too many generated confirmation codes are not unique!")
		}
	}
	return confirmationCode, nil
}

// Check that the given username and password are different.
// Also check if the chosen username only contains letters, numbers and/or underscore.
func ValidUsernamePassword(username, password string) error {
	// TODO Use a more international selection of letters?
	const allowed_letters = "abcdefghijklmnopqrstuvwxyzæøåABCDEFGHIJKLMNOPQRSTUVWXYZÆØÅ_0123456789"
NEXT:
	for _, letter := range username {
		for _, allowedLetter := range allowed_letters {
			if letter == allowedLetter {
				continue NEXT // check the next letter in the username
			}
		}
		return errors.New("Only letters, numbers and underscore are allowed in usernames.")
	}
	if username == password {
		return errors.New("Username and password must be different, try another password.")
	}
	return nil
}
