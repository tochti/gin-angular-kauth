package aauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	TestDBURL        = "mongodb://127.0.0.1:27017"
	TestDBName       = "testing-db"
	TestSessionsColl = "Session"
)

type (
	TestRequest struct {
		Body    string
		Handler http.Handler
		Header  http.Header
	}

	TestUser struct {
		name     string
		password string
	}

	TestSessionStore struct {
		token   string
		user    string
		expires time.Time
	}
)

func (u TestUser) FindUser(name string) (User, error) {
	return u, nil
}

func (u TestUser) ValidPassword(pass string) bool {
	return u.password == pass
}

func (u TestUser) ID() string {
	return u.name
}

func (u TestUser) Password() string {
	return u.password
}

func (s TestSessionStore) NewSession(id string, expires time.Time) (string, error) {
	return s.token, nil
}

func (s TestSessionStore) ReadSession(id string) (Session, bool) {
	if id != s.token || s.expires.Before(time.Now()) {
		return nil, false
	}

	return s, true
}

func (s TestSessionStore) RemoveSession(id string) error {
	return nil
}

func (s TestSessionStore) RemoveExpiredSessions() (int, error) {
	return 0, nil
}

func (s TestSessionStore) Token() string {
	return s.token
}

func (s TestSessionStore) Expires() time.Time {
	return s.expires
}

func (s TestSessionStore) UserID() string {
	return s.user
}

func (t *TestRequest) SendWithToken(method, path, token string) *httptest.ResponseRecorder {
	reqData := *t
	body := bytes.NewBufferString(reqData.Body)
	reqData.Header.Add("X-XSRF-TOKEN", token)

	req, _ := http.NewRequest(method, path, body)
	req.Header = reqData.Header
	w := httptest.NewRecorder()
	reqData.Handler.ServeHTTP(w, req)
	*t = reqData
	return w
}

func (t *TestRequest) Send(method, path string) *httptest.ResponseRecorder {
	reqData := *t
	body := bytes.NewBufferString(reqData.Body)

	req, _ := http.NewRequest(method, path, body)
	w := httptest.NewRecorder()
	reqData.Handler.ServeHTTP(w, req)
	*t = reqData
	return w
}

func ParseSignInResponse(r *bytes.Buffer) (SuccessResponse, error) {

	resp := SuccessResponse{}
	err := json.Unmarshal(r.Bytes(), &resp)
	if err != nil {
		return SuccessResponse{}, err
	}

	if resp.Status != "success" {
		m := fmt.Sprintf("Wrong status %v", resp.Status)
		return SuccessResponse{}, errors.New(m)
	}

	v, ok := resp.Data.(map[string]interface{})
	if !ok {
		return SuccessResponse{}, errors.New("Wrong data type")
	}

	id, ok := v["ID"].(string)
	if !ok {
		return SuccessResponse{}, errors.New("Wrong id type")
	}

	data := UserIDData{
		ID: id,
	}

	return NewSuccessResponse(data), nil
}

func ParseFailResponse(r *bytes.Buffer) (FailResponse, error) {
	resp := FailResponse{}
	err := json.Unmarshal(r.Bytes(), &resp)
	if err != nil {
		return FailResponse{}, err
	}

	return resp, nil
}

func EqualSignInResponse(r1, r2 SuccessResponse) error {
	if r1.Status != r2.Status {
		return errors.New("Unequal status")
	}

	id1, ok := r1.Data.(UserIDData)
	if !ok {
		return errors.New("Wrong data in r1")
	}
	id2, ok := r1.Data.(UserIDData)
	if !ok {
		return errors.New("Wrong data in r2")
	}

	if id1 != id2 {
		return errors.New("Unequal ids")
	}

	return nil

}

func EqualFailResponse(r1, r2 FailResponse) error {
	if r1.Status != r2.Status {
		return errors.New("Unequal status")
	}
	if r1.Err != r2.Err {
		return errors.New("Unequal error")
	}

	return nil
}

func EqualSession(s1, s2 SessionData) error {
	if s1.Token == s2.Token &&
		s1.UserID == s2.UserID &&
		s1.Expires.Equal(s2.Expires) {
		return nil
	}

	m := fmt.Sprintf("Expect", s1, "was", s2)
	return errors.New(m)
}

func ValidSignInCookie(r *httptest.ResponseRecorder) error {

	v, ok := r.HeaderMap["Set-Cookie"]
	if !ok {
		m := fmt.Sprintf("Expect a cookie was %v", r.HeaderMap)
		return errors.New(m)
	}
	if !strings.Contains(v[0], XSRFCookieName) {
		m := fmt.Sprintf("Expect %v was %v",
			XSRFCookieName, r.HeaderMap)
		return errors.New(m)
	}

	return nil
}

func ExistsToken(tokens []string, t string) bool {
	for _, e := range tokens {
		if t == e {
			return false
		}
	}

	return true
}

func Test_NewSha512Password_OK(t *testing.T) {
	tokens := []string{}
	for x := 0; x < 10; x++ {
		token := NewSha512Password(string(x))
		if !ExistsToken(tokens, token) {
			t.Fatal("Expect every token to be unique", token)
		}
		tokens = append(tokens, token)
	}
}

func Test_VerifyAuth_OK(t *testing.T) {
	sessionStore := TestSessionStore{
		token:   "123",
		user:    "lovemaster_XXX",
		expires: time.Now().Add(1 * time.Hour),
	}

	h := gin.New()
	// Test if session key in gin context
	afterAuth := func(c *gin.Context) {
		se, ok := c.Get(GinContextField)
		if !ok {
			m := fmt.Sprintf("Missing Field %v", GinContextField)
			t.Fatal(m)
		}
		c.JSON(http.StatusOK, se)
	}
	signedIn := SignedIn(sessionStore)
	h.GET("/", signedIn(afterAuth))

	request := TestRequest{
		Body:    "",
		Header:  http.Header{},
		Handler: h,
	}
	response := request.SendWithToken("GET", "/", sessionStore.Token())

	if response.Code != 200 {
		t.Fatal("Expect http-status 200 was", response.Code)
	}

	session := SessionData{}
	err := json.Unmarshal(response.Body.Bytes(), &session)
	if err != nil {
		t.Fatal(err.Error())
	}

	if session.UserID != sessionStore.UserID() {
		t.Fatal("Expect", sessionStore.UserID(), "was", session.UserID)
	}

	if session.Token != sessionStore.Token() {
		t.Fatal("Expect", sessionStore.Token(), "was", session.Token)
	}

}

func Test_VerifyAuth_Fail(t *testing.T) {
	sessionStore := TestSessionStore{
		user:    "pimp1999",
		token:   "123",
		expires: time.Now().Add(1 * time.Hour),
	}

	signedIn := SignedIn(sessionStore)
	afterAuth := func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"Status": "success"})
	}

	h := gin.New()
	h.GET("/", signedIn(afterAuth))
	request := TestRequest{
		Body:    "",
		Header:  http.Header{},
		Handler: h,
	}
	response := request.SendWithToken("GET", "/", "12")

	if response.Code != 401 {
		t.Fatal("Expect http-status 401 was", response.Code)
	}

}

func Test_VerifyAuth_ExpiresFail(t *testing.T) {
	sessionStore := TestSessionStore{
		token:   "123",
		user:    "Schnecke1987",
		expires: time.Now().Add(-1 * time.Hour),
	}
	signedIn := SignedIn(sessionStore)
	afterAuth := func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"Status": "success"})
	}
	h := gin.New()
	h.GET("/", signedIn(afterAuth))
	request := TestRequest{
		Body:    "",
		Header:  http.Header{},
		Handler: h,
	}

	response := request.SendWithToken("GET", "/", "123")

	if response.Code != 401 {
		t.Fatal("Expect http-status 401 was", response.Code)
	}

}

func Test_GET_SignIn_OK(t *testing.T) {
	userStore := TestUser{
		name:     "ladykiller_XX",
		password: "123",
	}

	sessionStore := TestSessionStore{
		user:    userStore.name,
		token:   "544",
		expires: time.Now().Add(1 * time.Hour),
	}

	handler := gin.New()
	req := TestRequest{
		Body:    "",
		Header:  http.Header{},
		Handler: handler,
	}

	h := SignIn(sessionStore, userStore)
	handler.GET("/:name/:password", h)

	url := fmt.Sprintf("/%v/%v", userStore.name, userStore.password)
	resp := req.Send("GET", url)

	userID := UserIDData{
		ID: userStore.name,
	}
	expectResp := NewSuccessResponse(userID)

	result, err := ParseSignInResponse(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	err = EqualSignInResponse(expectResp, result)
	if err != nil {
		t.Fatal(err)
	}

	err = ValidSignInCookie(resp)
	if err != nil {
		t.Fatal(err)
	}

}

func Test_GET_SignIn_Fail(t *testing.T) {
	userStore := TestUser{
		name:     "cooldancer_123",
		password: "123",
	}
	sessionStore := TestSessionStore{
		user:    userStore.name,
		token:   "444",
		expires: time.Now().Add(1 * time.Hour),
	}

	handler := gin.New()
	req := TestRequest{
		Body:    "",
		Header:  http.Header{},
		Handler: handler,
	}

	h := SignIn(sessionStore, userStore)
	handler.GET("/:name/:pass", h)

	url := fmt.Sprintf("/%v/%v", userStore.name, "wrong")
	resp := req.Send("GET", url)

	resultResp, err := ParseFailResponse(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	expectResp := NewFailResponse(SignInErr)
	err = EqualFailResponse(expectResp, resultResp)
	if err != nil {
		t.Fatal(err)
	}

}

func Test_ReadSession_OK(t *testing.T) {
	ctx := &gin.Context{}

	session := SessionData{
		UserID:  "",
		Token:   "",
		Expires: time.Now(),
	}

	ctx.Set(GinContextField, session)

	result, err := ReadSession(ctx)
	if err != nil {
		t.Fatal(err)
	}

	err = EqualSession(session, result)
	if err != nil {
		t.Fatal(err)
	}
}
