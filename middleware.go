package userstate

// The middleware handler

import (
	"log"
	"net/http"
	"strings"
)

var (
	userpages  []string
	adminpages []string
)

func OnlyUsers(url string) {
	userpages = append(userpages, url)
}

func OnlyAdmin(url string) {
	adminpages = append(adminpages, url)
}

func (state *UserState) ServeHTTP(rw http.ResponseWriter, req *http.Request, next http.HandlerFunc) {

	path := req.URL.Path

	for _, up := range userpages {
		if strings.HasPrefix(path, up) {
			log.Println("MUST BE USER TO ACCESS " + path)
			break
		}
	}

	for _, ap := range adminpages {
		if strings.HasPrefix(path, ap) {
			log.Println("MUST BE USER TO ACCESS " + path)
			break
		}
	}

	// Call the next middleware handler
	next(rw, req)
}
