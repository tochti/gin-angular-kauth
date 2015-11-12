Angular "kind of auth" for gin
==============================

Man kann per default in Angular zu Authentifikation einer Sitzung den CSRF Token verwenden.
Hier ist definiert das wenn ein Response ein Cookien mit einen bestimmten Namen enthält der hinterlegt Token bei allen weiteren Request im Header mitgesendet werden. In diesem Paket enthalten sind Handler für diesen Zweck.

Zum einem gibt es die Möglichkeit einen Benutzer anzumelden und einen Session dafür anzulegen.
Zum zweiten gibt es ein Handler Wrapper um zu prüfen ob ein Benutzer angelemdet ist.

```go

func handler(c *gin.Context) {
    c.String(200, "Secret!")
}

func main () {
    // user ist ein Objekt welches das UserSignIn interface implementiert
    // sessionStore ist ein Object welches das SessionStore interface implementiert
    signIn := kauth.SignIn(user, sessionStore)
    signedIn := kauth.SignedIn(sessionStore)

    srv := gin.New()
    // :user ist der String mittels dem die FindUser Funktionen den Benutzer Indetifizieren kann, Mail oder Benutzername
    srv.GET("/SignIn/:name/:password", signIn)
    srv.GET("/", signedIn(handler))
    srv.Run()
}

```
