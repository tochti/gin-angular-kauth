package aauth

import (
	"crypto/sha512"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
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

	ErrorHandler func(*gin.Context) error

	UserIDData struct {
		ID string
	}

	SessionData struct {
		Token   string    `bson:"Token"`
		UserID  string    `bson:"UserID"`
		Expires time.Time `bson:"Expires"`
	}

	Session interface {
		Token() string
		UserID() string
		Expires() time.Time
	}

	SessionStore interface {
		NewSession(string, time.Time) (string, error)
		ReadSession(string) (Session, bool)
		RemoveSession(string) error
		RemoveExpiredSessions() (int, error)
	}

	User interface {
		ID() string
		Password() string
	}

	UserStore interface {
		FindUser(string) (User, error)
		ValidPassword(string) bool
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

func ReadSession(c *gin.Context) (SessionData, error) {
	v, ok := c.Get(GinContextField)
	if !ok {
		return SessionData{}, CookieErr
	}

	s, ok := v.(SessionData)
	if !ok {
		return SessionData{}, CookieErr
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

func SignedIn(s SessionStore) func(gin.HandlerFunc) gin.HandlerFunc {
	return func(h gin.HandlerFunc) gin.HandlerFunc {
		return func(c *gin.Context) {
			err := Bouncer(c, s)
			if err != nil {
				c.JSON(http.StatusUnauthorized,
					NewFailResponse(err))
			}

			h(c)
		}

	}
}

func Bouncer(c *gin.Context, s SessionStore) error {
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

	ctxSession := SessionData{
		Token:   session.Token(),
		UserID:  session.UserID(),
		Expires: session.Expires(),
	}

	c.Set(GinContextField, ctxSession)
	return nil
}

func SignIn(s SessionStore, u UserStore) gin.HandlerFunc {
	handler := func(c *gin.Context) error {
		return Signer(c, s, u)
	}

	return ErrorWrap(handler)

}

func Signer(c *gin.Context, s SessionStore, u UserStore) error {
	name := c.Params.ByName(NameRequestField)
	pass := c.Params.ByName(PassRequestField)

	user, err := u.FindUser(name)
	if err != nil {
		return err
	}

	if !u.ValidPassword(pass) {
		return SignInErr
	}

	resp := NewSuccessResponse(UserIDData{
		ID: user.ID(),
	})

	expire := time.Now().Add(24 * time.Hour)
	token, err := s.NewSession(user.ID(), expire)
	if err != nil {
		return err
	}

	session := SessionData{
		UserID:  user.ID(),
		Token:   token,
		Expires: expire,
	}

	c.Set(GinContextField, session)

	cookie := http.Cookie{
		Name:    XSRFCookieName,
		Value:   token,
		Expires: expire,
		// Setze Path auf / ansonsten kann angularjs
		// diese Cookie nicht finden und in späteren
		// Request nicht mitsenden.
		Path: "/",
	}

	http.SetCookie(c.Writer, &cookie)

	c.JSON(http.StatusOK, resp)

	return nil
}
