package aauth

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

const (
	GinContextField  = "Session"
	XSRFCookieName   = "XSRF-TOKEN"
	TokenHeaderField = "X-XSRF-TOKEN"
	NameRequestField = "name"
	PassRequestField = "pass"
)

var (
	SignInErr = errors.New("Sign in error")
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

	UserIDData struct {
		ID string
	}

	Session struct {
		Token   string    `bson:"Token"`
		UserID  string    `bson:"UserID"`
		Expires time.Time `bson:"Expires"`
	}

	User interface {
		ID() string
		Password() string
	}

	FindUser func(string) (User, error)
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

// Middleware Decorator:
// Handles Angularjs Default Authentication
// Sendet man über den angular http Serviecs ein Request und erhält
// daraufhin ein Response mit einem Cookie welcher ein XSRF-Token Feld
// enthält wird der hinterlegte Token für zukünftige Request verwendet.
// Der Token wird als HTTP-Header-Feld X-XSRF-Token versand. Diesen
// Eigenschaft kann man für die Benutzer Authentifikation verwenden.
//
// Die Middleware fügt ein Feld Session zum gin Context.
//
// Die Middleware erwartet ein Session Collection mit den selben
// Feldern wie der Session Typ
//
// Example:
// app := gin.New()
//
// func protectedHandler(c *gin.Context) {
//      // Access only for succesfully authenticated user
// }
//
// s,_ := db.Dial("mongodb://127.0.0.1:27017")
// db := s.DB("DBName")
// auth := AngularAuth(*mgo.Database, "SessionCollName")
// app.GET(auth, portectedHandler)
//
func AngularAuth(db *mgo.Database, coll string) gin.HandlerFunc {
	return func(c *gin.Context) {
		err := Auther(c, db, coll)
		if err != nil {
			c.JSON(http.StatusUnauthorized,
				NewFailResponse(err))
			c.Abort()
		}
	}
}

func Auther(c *gin.Context, db *mgo.Database, sessionsColl string) error {
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

	coll := db.C(sessionsColl)
	find := coll.Find(bson.M{"Token": token})
	n, err := find.Count()
	if err != nil {
		return err
	}
	if n != 1 {
		return errors.New("Session not found")

	}

	session := Session{}
	err = find.One(&session)
	if err != nil {
		return err
	}
	if session.Expires.Before(time.Now()) {
		return errors.New("Session expired")
	}

	c.Set(GinContextField, session)
	c.Next()
	return nil
}

// Sign in func
// Die Funktion erwartet folgende Parameter
func AngularSignIn(fun FindUser) gin.HandlerFunc {
	return func(c *gin.Context) {
		err := Signer(c, fun)
		if err != nil {
			c.JSON(http.StatusUnauthorized,
				NewFailResponse(err))
		}
	}
}

func Signer(c *gin.Context, fun FindUser) error {
	name := c.Params.ByName(NameRequestField)
	pass := c.Params.ByName(PassRequestField)

	user, err := fun(name)
	if err != nil {
		return err
	}

	if user.Password() != pass {
		return SignInErr
	}

	resp := NewSuccessResponse(UserIDData{
		ID: user.ID(),
	})
	c.JSON(http.StatusOK, resp)

	return nil
}
