package userstate

import (
	"errors"
	"math/rand"
	"strings"
)

const (
	USERNAME_ALLOWED_LETTERS = "abcdefghijklmnopqrstuvwxyzæøåABCDEFGHIJKLMNOPQRSTUVWXYZÆØÅ_0123456789"
)

// Converts "true" or "false" to a bool
func TruthValue(val string) bool {
	return "true" == val
}

// Split a string at the colon into two strings
// If there's no colon, return the string and an empty string
func ColonSplit(s string) (string, string) {
	if strings.Contains(s, ":") {
		sl := strings.SplitN(s, ":", 2)
		return sl[0], sl[1]
	}
	return s, ""
}

func Min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TableCell(b bool) string {
	if b {
		return "<td class=\"yes\">yes</td>"
	}
	return "<td class=\"no\">no</td>"
}

func RandomString(length int) string {
	b := make([]byte, length)
	for i := 0; i < length; i++ {
		b[i] = byte(rand.Int63() & 0xff)
	}
	return string(b)
}

func RandomHumanFriendlyString(length int) string {
	const (
		vowels     = "aeiouy" // email+browsers didn't like "æøå" too much
		consonants = "bcdfghjklmnpqrstvwxz"
	)
	b := make([]byte, length)
	for i := 0; i < length; i++ {
		if i%2 == 0 {
			b[i] = vowels[rand.Intn(len(vowels))]
		} else {
			b[i] = consonants[rand.Intn(len(consonants))]
		}
	}
	return string(b)
}

func RandomCookieFriendlyString(length int) string {
	const ALLOWED = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := 0; i < length; i++ {
		b[i] = ALLOWED[rand.Intn(len(ALLOWED))]
	}
	return string(b)
}

func CleanUserInput(val string) string {
	return strings.Replace(val, "<", "&lt;", -1)
}

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
