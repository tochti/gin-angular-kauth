package kauth

import (
	"crypto/sha512"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tochti/session-store"
)

const (
	GinContextField  = "Session"
	XSRFCookieName   = "XSRF-TOKEN"
	TokenHeaderField = "X-XSRF-TOKEN"
	NameRequestField = "name"
	PassRequestField = "password"
)

var (
	SignInErr = errors.New("Sign in error")
	CookieErr = errors.New("Cookie error")
)

type (
	SuccessResponse struct {
		Status string
		Data   interface{}
	}

	FailResponse struct {
		Status string
		Err    string
	}

	SessionResponse struct {
		Token   string
		UserID  string
		Expires time.Time
	}

	ErrorHandler func(*gin.Context) error

	UserIDData struct {
		ID string
	}

	User interface {
		ID() string
		Password() string
		ValidPassword(string) bool
	}

	UserStore interface {
		FindUser(string) (User, error)
	}
)

func NewSuccessResponse(data interface{}) SuccessResponse {
	return SuccessResponse{
		Status: "success",
		Data:   data,
	}
}

func NewFailResponse(err interface{}) FailResponse {
	return FailResponse{
		Status: "fail",
		Err:    fmt.Sprintf("%v", err),
	}
}

func NewSha512Password(pass string) string {
	hash := sha512.New()
	tmp := hash.Sum([]byte(pass))
	passHash := fmt.Sprintf("%x", tmp)
	return passHash
}

func ReadSession(c *gin.Context) (s2tore.Session, error) {
	v, ok := c.Get(GinContextField)
	if !ok {
		return nil, CookieErr
	}

	s, ok := v.(s2tore.Session)
	if !ok {
		return nil, CookieErr
	}

	return s, nil
}

func ErrorWrap(h ErrorHandler) gin.HandlerFunc {
	return func(c *gin.Context) {
		err := h(c)
		if err != nil {
			c.JSON(http.StatusUnauthorized,
				NewFailResponse(err))
		}
	}

}

func SignedIn(s s2tore.SessionStore) func(gin.HandlerFunc) gin.HandlerFunc {
	return func(h gin.HandlerFunc) gin.HandlerFunc {
		return func(c *gin.Context) {
			err := Bouncer(c, s)
			if err != nil {
				c.JSON(http.StatusUnauthorized,
					NewFailResponse(err))
				return
			}

			h(c)
		}

	}
}

func Bouncer(c *gin.Context, s s2tore.SessionStore) error {
	token := c.Request.Header.Get(TokenHeaderField)
	if token == "" {
		cookie, err := c.Request.Cookie(XSRFCookieName)
		if err != nil {
			return errors.New("Cookie not found")
		}
		token = cookie.Value
		if token == "" {
			return errors.New("Header not found")
		}
	}

	session, ok := s.ReadSession(token)
	if !ok {
		return errors.New("Session not found")

	}

	c.Set(GinContextField, session)
	return nil
}

func SignIn(s s2tore.SessionStore, u UserStore) gin.HandlerFunc {
	handler := func(c *gin.Context) error {
		return Signer(c, s, u)
	}

	return ErrorWrap(handler)

}

func Signer(c *gin.Context, s s2tore.SessionStore, u UserStore) error {
	name := c.Params.ByName(NameRequestField)
	pass := c.Params.ByName(PassRequestField)

	user, err := u.FindUser(name)
	if err != nil {
		return err
	}

	if !user.ValidPassword(pass) {
		return SignInErr
	}

	expire := time.Now().Add(24 * time.Hour)
	session, err := s.NewSession(user.ID(), expire)
	if err != nil {
		return err
	}

	c.Set(GinContextField, session)

	resp := NewSuccessResponse(SessionResponse{
		Token:   session.Token(),
		UserID:  session.UserID(),
		Expires: session.Expires(),
	})

	cookie := http.Cookie{
		Name:    XSRFCookieName,
		Value:   session.Token(),
		Expires: session.Expires(),
		// Setze Path auf / ansonsten kann angularjs
		// diese Cookie nicht finden und in späteren
		// Request nicht mitsenden.
		Path: "/",
	}

	http.SetCookie(c.Writer, &cookie)

	c.JSON(http.StatusOK, resp)

	return nil
}
