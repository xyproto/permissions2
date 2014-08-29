package userstate

import "errors"

const (
	USERNAME_ALLOWED_LETTERS = "abcdefghijklmnopqrstuvwxyzæøåABCDEFGHIJKLMNOPQRSTUVWXYZÆØÅ_0123456789"
)

func Check(username, password, email string) error {
NEXT:
	for _, letter := range username {
		for _, allowedLetter := range USERNAME_ALLOWED_LETTERS {
			if letter == allowedLetter {
				continue NEXT
			}
		}
		return errors.New("Only a-å, A-Å, 0-9 and _ are allowed in usernames.")
	}
	if username == password {
		return errors.New("Username and password must be different, try another password.")
	}
	return nil
}
