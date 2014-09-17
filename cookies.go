package permissions

// Thanks to web.go for several of these functions

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	defaultCookieTime = 3600 * 24 // Login cookies should last for 24 hours, by default
)

func GetSecureCookie(req *http.Request, name string, cookieSecret string) (string, bool) {
	for _, cookie := range req.Cookies() {
		if cookie.Name != name {
			continue
		}

		parts := strings.SplitN(cookie.Value, "|", 3)

		val := parts[0]
		timestamp := parts[1]
		sig := parts[2]

		if getCookieSig(cookieSecret, []byte(val), timestamp) != sig {
			return "", false
		}

		ts, _ := strconv.ParseInt(timestamp, 0, 64)

		if time.Now().Unix()-31*86400 > ts {
			return "", false
		}

		buf := bytes.NewBufferString(val)
		encoder := base64.NewDecoder(base64.StdEncoding, buf)

		res, _ := ioutil.ReadAll(encoder)
		return string(res), true
	}
	return "", false
}

func SetSecureCookiePath(w http.ResponseWriter, name, val string, age int64, path string, cookieSecret string) {
	// base64 encode the value
	if len(cookieSecret) == 0 {
		log.Fatalln("Secret Key for secure cookies has not been set. Please use a non-empty secret.")
	}
	var buf bytes.Buffer
	encoder := base64.NewEncoder(base64.StdEncoding, &buf)
	encoder.Write([]byte(val))
	encoder.Close()
	vs := buf.String()
	vb := buf.Bytes()
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	sig := getCookieSig(cookieSecret, vb, timestamp)
	cookie := strings.Join([]string{vs, timestamp, sig}, "|")
	SetCookiePath(w, name, cookie, age, path)
}

// Set a cookie with an explicit path. Duration is the cookie time-to-live in
// seconds (0 = forever).
func SetCookiePath(w http.ResponseWriter, name, value string, age int64, path string) {
	var utctime time.Time
	if age == 0 {
		// 2^31 - 1 seconds (roughly 2038)
		utctime = time.Unix(2147483647, 0)
	} else {
		utctime = time.Unix(time.Now().Unix()+age, 0)
	}
	cookie := http.Cookie{Name: name, Value: value, Expires: utctime, Path: path}
	SetHeader(w, "Set-Cookie", cookie.String(), false)
}

func getCookieSig(key string, val []byte, timestamp string) string {
	hm := hmac.New(sha1.New, []byte(key))

	hm.Write(val)
	hm.Write([]byte(timestamp))

	hex := fmt.Sprintf("%02x", hm.Sum(nil))
	return hex
}

// Used for setting cookies
func SetHeader(rw http.ResponseWriter, hdr, val string, unique bool) {
	if unique {
		rw.Header().Set(hdr, val)
	} else {
		rw.Header().Add(hdr, val)
	}
}
