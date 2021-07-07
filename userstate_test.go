package permissions

import (
	"github.com/xyproto/pinterface"
	"testing"
	"time"
)

func TestPerm(t *testing.T) {
	userstate := NewUserStateSimple()

	userstate.AddUser("bob", "hunter1", "bob@zombo.com")

	if !userstate.HasUser("bob") {
		t.Error("Error, user bob should exist")
	}

	if userstate.IsConfirmed("bob") {
		t.Error("Error, user bob should not be confirmed right now.")
	}

	userstate.MarkConfirmed("bob")

	if !userstate.IsConfirmed("bob") {
		t.Error("Error, user bob should be marked as confirmed right now.")
	}

	if userstate.IsAdmin("bob") {
		t.Error("Error, user bob should not have admin rights")
	}

	userstate.SetAdminStatus("bob")

	if !userstate.IsAdmin("bob") {
		t.Error("Error, user bob should have admin rights")
	}

	userstate.RemoveUser("bob")

	if userstate.HasUser("bob") {
		t.Error("Error, user bob should not exist")
	}
}

func TestPasswordBasic(t *testing.T) {
	userstate := NewUserStateSimple()

	// Assert that the default password algorithm is "bcrypt+"
	if userstate.PasswordAlgo() != "bcrypt+" {
		t.Error("Error, bcrypt+ should be the default password algorithm")
	}

	// Set password algorithm
	userstate.SetPasswordAlgo("sha256")

	// Assert that the algorithm is now sha256
	if userstate.PasswordAlgo() != "sha256" {
		t.Error("Error, setting password algorithm failed")
	}

}

func TestPasswordBasic2(t *testing.T) {
	// Test the other method for connecting to Redis
	userstate, err := NewUserStateSimple2()
	if err != nil {
		t.Error("Error, " + err.Error())
	}

	// Assert that the default password algorithm is "bcrypt+"
	if userstate.PasswordAlgo() != "bcrypt+" {
		t.Error("Error, bcrypt+ should be the default password algorithm")
	}

	// Set password algorithm
	userstate.SetPasswordAlgo("sha256")

	// Assert that the algorithm is now sha256
	if userstate.PasswordAlgo() != "sha256" {
		t.Error("Error, setting password algorithm failed")
	}

}

// Check if the functionality for backwards compatible hashing works
func TestPasswordBackward(t *testing.T) {
	userstate := NewUserStateSimple()
	userstate.SetPasswordAlgo("sha256")
	userstate.AddUser("bob", "hunter1", "bob@zombo.com")
	if !userstate.HasUser("bob") {
		t.Error("Error, user bob should exist")
	}
	defer userstate.RemoveUser("bob")

	userstate.SetPasswordAlgo("sha256")
	if !userstate.CorrectPassword("bob", "hunter1") {
		t.Error("Error, the sha256 password really is correct")
	}

	userstate.SetPasswordAlgo("bcrypt")
	if userstate.CorrectPassword("bob", "hunter1") {
		t.Error("Error, the password as stored as sha256, not bcrypt")
	}

	userstate.SetPasswordAlgo("bcrypt+")
	if !userstate.CorrectPassword("bob", "hunter1") {
		t.Error("Error, the sha256 password is not correct when checking with bcrypt+")
	}
}

// Check if the functionality for backwards compatible hashing works
func TestPasswordNotBackward(t *testing.T) {
	userstate := NewUserStateSimple()
	userstate.SetPasswordAlgo("bcrypt")
	userstate.AddUser("bob", "hunter1", "bob@zombo.com")
	if !userstate.HasUser("bob") {
		t.Error("Error, user bob should exist")
	}
	defer userstate.RemoveUser("bob")

	userstate.SetPasswordAlgo("sha256")
	if userstate.CorrectPassword("bob", "hunter1") {
		t.Error("Error, the password is stored as bcrypt, should not be okay with sha256")
	}

	userstate.SetPasswordAlgo("bcrypt")
	if !userstate.CorrectPassword("bob", "hunter1") {
		t.Error("Error, the password should be correct when checking with bcrypt")
	}
}

func TestPasswordAlgoMatching(t *testing.T) {
	userstate := NewUserStateSimple()
	// generate two different password using the same credentials but different algos
	userstate.SetPasswordAlgo("sha256")
	sha256Hash := userstate.HashPassword("testuser@example.com", "textpassword")
	userstate.SetPasswordAlgo("bcrypt")
	bcryptHash := userstate.HashPassword("testuser@example.com", "textpassword")

	// they shouldn't match
	if sha256Hash == bcryptHash {
		t.Error("Error, different algorithms should not have a password match")
	}
}

func TestUserStateKeeper(t *testing.T) {
	userstate := NewUserStateSimple()

	// Check that the userstate qualifies for the IUserState interface
	var _ pinterface.IUserState = userstate
}

func TestHostPassword(t *testing.T) {
	//userstate := NewUserStateWithPassword("localhost", "foobared")
	userstate := NewUserStateWithPassword("localhost", "")

	userstate.AddUser("bob", "hunter1", "bob@zombo.com")
	if !userstate.HasUser("bob") {
		t.Error("Error, user bob should exist")
	}

	// Remove bob
	userstate.RemoveUser("bob")
	if userstate.HasUser("bob") {
		t.Error("Error, user bob should not exist")
	}
}

func TestChangePassword(t *testing.T) {
	userstate := NewUserStateSimple()

	userstate.AddUser("bob", "hunter1", "bob@zombo.com")
	if !userstate.HasUser("bob") {
		t.Error("Error, user bob should exist")
	}
	defer userstate.RemoveUser("bob")

	// Check that the password is "hunter1"
	if !userstate.CorrectPassword("bob", "hunter1") {
		t.Error("Error, password is incorrect: should be hunter1!")
	}
	// Check that the password is not "hunter2"
	if userstate.CorrectPassword("bob", "hunter2") {
		t.Error("Error, password is incorrect: should not be hunter2!")
	}

	// Change the password for user "bob" to "hunter2"
	username := "bob"
	password := "hunter2"
	passwordHash := userstate.HashPassword(username, password)
	userstate.Users().Set(username, "password", passwordHash)

	// Check that the password is "hunter2"
	if !userstate.CorrectPassword("bob", "hunter2") {
		t.Error("Error, password is incorrect: should be hunter2!")
	}
	// Check that the password is not "hunter1"
	if userstate.CorrectPassword("bob", "hunter1") {
		t.Error("Error, password is incorrect: should not be hunter1!")
	}

	// Change the password back to "hunter1"
	userstate.SetPassword("bob", "hunter1")

	// Check that the password is "hunter1"
	if !userstate.CorrectPassword("bob", "hunter1") {
		t.Error("Error, password is incorrect: should be hunter1!")
	}
	// Check that the password is not "hunter2"
	if userstate.CorrectPassword("bob", "hunter2") {
		t.Error("Error, password is incorrect: should not be hunter2!")
	}

	if len(userstate.Properties("bob")) != 5 {
		t.Error("Error, there should be 5 properties on bob now!")
	}
}

func TestTokens(t *testing.T) {
	userstate := NewUserStateSimple()

	// Add bob
	userstate.AddUser("bob", "hunter1", "bob@zombo.com")
	if !userstate.HasUser("bob") {
		t.Error("Error, user bob should exist")
	}
	defer userstate.RemoveUser("bob")

	// Set a token that will expire in 200 milliseconds
	userstate.SetToken("bob", "asdf123", time.Millisecond*200)

	// Check that the token is "asdf123"
	retval, err := userstate.GetToken("bob")
	if err != nil {
		t.Error("Error, could not get token")
	}
	if retval != "asdf123" {
		t.Error("Error, token is incorrect: should be asdf123!")
	}

	// Wait 400 milliseconds
	time.Sleep(time.Millisecond * 400)

	// Check that the token is now gone
	retval, err = userstate.GetToken("bob")
	if err == nil || retval != "" {
		t.Error("Error, token is incorrect: should be gone!")
	}
}

func TestEmail(t *testing.T) {
	userstate := NewUserStateSimple()
	userstate.AddUser("bob", "hunter1", "bob@zombo.com")
	username, err := userstate.HasEmail("bob@zombo.com")
	if err != nil {
		t.Error("Error, the e-mail should exist:", err)
	}
	if username != "bob" {
		t.Error("Error, the e-mail address should belong to bob, but belongs to:", username)
	}
	username, err = userstate.HasEmail("rob@zombo.com")
	if err != ErrNotFound {
		t.Error("Error, the e-mail should not exist: " + username)
	}
}

func TestTiming(t *testing.T) {
	userstate := NewUserStateSimple()

	userstate.SetPasswordAlgo("bcrypt")
	userstate.AddUser("bob", "hunter1", "bob@zombo.com")
	if !userstate.HasUser("bob") {
		t.Error("Error, user bob should exist")
	}
	defer userstate.RemoveUser("bob")

	// First run takes a bit longer
	_ = userstate.CorrectPassword("bob", "asdf")

	start1 := time.Now()
	if !userstate.CorrectPassword("bob", "hunter1") {
		t.Error("Error, the password IS correct")
	}
	elapsed1 := time.Since(start1)

	start2 := time.Now()
	if userstate.CorrectPassword("bob", "_") {
		t.Error("Error, the password is NOT correct")
	}
	elapsed2 := time.Since(start2)

	start3 := time.Now()
	if userstate.CorrectPassword("bob", "abc123asfdasdfasfasdfqwertyqwertyqwerty") {
		t.Error("Error, the password is NOT correct")
	}
	elapsed3 := time.Since(start3)

	start4 := time.Now()
	if userstate.CorrectPassword("bob", "abc123asfdasdfasfasdfqwertyqwertyqwertyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy") {
		t.Error("Error, the password is NOT correct")
	}
	elapsed4 := time.Since(start4)

	// The tolerance is +- one of the first elapsed times. Hard to find a good value here, since the values differ from machine to machine.
	baseMin := elapsed1 - time.Duration(elapsed1)
	baseMax := elapsed1 + time.Duration(elapsed1)

	if elapsed2 < baseMin || elapsed2 > baseMax {
		t.Error("Checking passwords of different lengths should not take much longer or shorter")
	}

	if elapsed3 < baseMin || elapsed3 > baseMax {
		t.Error("Checking passwords of different lengths should not take much longer or shorter")
	}

	if elapsed4 < baseMin || elapsed4 > baseMax {
		t.Error("Checking passwords of different lengths should not take much longer or shorter")
	}
	//fmt.Println(baseMin, base_max, elapsed1, elapsed2, elapsed3, elapsed4)
}
