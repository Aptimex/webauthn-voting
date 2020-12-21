package main

import (
	"encoding/json"
	//"time"
	"fmt"
	"log"
	"net/http"
	"strings"
	//"io"
	"context"
	"time"

	"github.com/duo-labs/webauthn.io/session"
	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
	"github.com/gorilla/mux"
)

var webAuthn *webauthn.WebAuthn
var userDB *userdb
var sessionStore *session.Store

func main() {

	serverAddress := ":9999"
	
	var err error
	webAuthn, err = webauthn.New(&webauthn.Config{
		RPDisplayName: "Foobar Corp.",     // Display Name for your site
		RPID:          "localhost",        // Generally the domain name for your site
		RPOrigin:      "http://localhost" + serverAddress, // The origin URL for WebAuthn requests
		// RPIcon: "https://duo.com/logo.png", // Optional icon URL for your site
	})

	if err != nil {
		log.Fatal("failed to create WebAuthn from config:", err)
	}

	userDB = DB()

	sessionStore, err = session.NewStore()
	if err != nil {
		log.Fatal("failed to create session store:", err)
	}

	r := mux.NewRouter()

	r.HandleFunc("/dump", dbDump).Methods("GET")
	r.HandleFunc("/logout", Logout).Methods("GET")
	r.HandleFunc("/verify/begin/{username}", BeginVerify).Methods("POST")
	r.HandleFunc("/verify/finish/{username}", FinishVerify).Methods("POST")
	r.HandleFunc("/vote", LoginRequired(CastBallot)).Methods("GET")

	r.HandleFunc("/register/begin/{username}", BeginRegistration).Methods("GET")
	r.HandleFunc("/register/finish/{username}", FinishRegistration).Methods("POST")
	r.HandleFunc("/login/begin/{username}", BeginLogin).Methods("GET")
	r.HandleFunc("/login/finish/{username}", FinishLogin).Methods("POST")

	r.PathPrefix("/").Handler(http.FileServer(http.Dir("./")))

	log.Println("starting server at", serverAddress)
	log.Fatal(http.ListenAndServe(serverAddress, r))
}

func dbDump(w http.ResponseWriter, r *http.Request) {
	//log.Printf("%+v\n", userDB.users)
	data := userDB.DumpDB()
	jsonResponse(w, data, http.StatusOK)
}

func CastBallot(w http.ResponseWriter, r *http.Request)  {
	/*
	session, _ := store.Get(r, "userAuth")
	
	// Check if user is authenticated
    if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
        http.Error(w, "Forbidden", http.StatusForbidden)
        return
    }
	*/
	
	//Auth success, send the file
	http.ServeFile(w, r, "voteCast.html")
}

//mostly the same as BeginLogin
func BeginVerify(w http.ResponseWriter, r *http.Request) {

	// get username
	vars := mux.Vars(r)
	username := vars["username"]
	
	var data string
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
	}

	// get user
	user, err := userDB.GetUser(username)

	// user doesn't exist
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// generate PublicKeyCredentialRequestOptions, session data
	options, sessionData, err := webAuthn.BeginVerify(user, data)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// store session data as marshaled JSON
	err = sessionStore.SaveWebauthnSession("authentication", sessionData, r, w)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonResponse(w, options, http.StatusOK)
}

//mostly the same as FinishLogin
func FinishVerify(w http.ResponseWriter, r *http.Request) {

	// get username
	vars := mux.Vars(r)
	username := vars["username"]

	// get user
	user, err := userDB.GetUser(username)

	// user doesn't exist
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// load the session data
	sessionData, err := sessionStore.GetWebauthnSession("authentication", r)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// in an actual implementation, we should perform additional checks on
	// the returned 'credential', i.e. check 'credential.Authenticator.CloneWarning'
	// and then increment the credentials counter
	_, veriData, err := webAuthn.FinishVerify(user, sessionData, r)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// handle successful login
	jsonResponse(w, veriData, http.StatusOK)
}

func BeginRegistration(w http.ResponseWriter, r *http.Request) {

	// get username/friendly name
	vars := mux.Vars(r)
	username, ok := vars["username"]
	if !ok {
		jsonResponse(w, fmt.Errorf("must supply a valid username i.e. foo@bar.com"), http.StatusBadRequest)
		return
	}

	// get user
	user, err := userDB.GetUser(username)
	// user doesn't exist, create new user
	if err != nil {
		displayName := strings.Split(username, "@")[0]
		user = NewUser(username, displayName)
		userDB.PutUser(user)
	}

	registerOptions := func(credCreationOpts *protocol.PublicKeyCredentialCreationOptions) {
		credCreationOpts.CredentialExcludeList = user.CredentialExcludeList()
	}

	// generate PublicKeyCredentialCreationOptions, session data
	options, sessionData, err := webAuthn.BeginRegistration(
		user,
		registerOptions,
	)

	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// store session data as marshaled JSON
	err = sessionStore.SaveWebauthnSession("registration", sessionData, r, w)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonResponse(w, options, http.StatusOK)
}

func FinishRegistration(w http.ResponseWriter, r *http.Request) {

	// get username
	vars := mux.Vars(r)
	username := vars["username"]

	// get user
	user, err := userDB.GetUser(username)
	// user doesn't exist
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// load the session data
	sessionData, err := sessionStore.GetWebauthnSession("registration", r)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	credential, err := webAuthn.FinishRegistration(user, sessionData, r)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	user.AddCredential(*credential)

	jsonResponse(w, "Registration Success", http.StatusOK)
}

func BeginLogin(w http.ResponseWriter, r *http.Request) {

	// get username
	vars := mux.Vars(r)
	username := vars["username"]

	// get user
	user, err := userDB.GetUser(username)

	// user doesn't exist
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// generate PublicKeyCredentialRequestOptions, session data
	options, sessionData, err := webAuthn.BeginLogin(user)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// store session data as marshaled JSON
	err = sessionStore.SaveWebauthnSession("authentication", sessionData, r, w)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonResponse(w, options, http.StatusOK)
}

func FinishLogin(w http.ResponseWriter, r *http.Request) {

	// get username
	vars := mux.Vars(r)
	username := vars["username"]

	// get user
	user, err := userDB.GetUser(username)

	// user doesn't exist
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// load the session data
	sessionData, err := sessionStore.GetWebauthnSession("authentication", r)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// in an actual implementation, we should perform additional checks on
	// the returned 'credential', i.e. check 'credential.Authenticator.CloneWarning'
	// and then increment the credentials counter
	_, err = webAuthn.FinishLogin(user, sessionData, r)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// handle successful login
	/*
	session, _ := store.Get(r, "userAuth")
	//Auth stuff already done above
	session.Values["authenticated"] = true
    session.Save(r, w)
	*/
	
	jsonResponse(w, "Login Success", http.StatusOK)
}

//modified from webauthn.io source code
// LoginRequired sets a context variable with the user loaded from the user ID
// stored in the session cookie
func LoginRequired(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		
		//session, _ := ws.store.Get(r, session.WebauthnSession)
		// load the session data
		session, err := sessionStore.GetWebauthnSession("authentication", r)
		if err != nil {
			log.Println(err)
			errorResponse(w, "Cannnot retrieve webauthn session: " + err.Error(), http.StatusBadRequest)
			return
		}
		if session.Challenge == "" {
			err = fmt.Errorf("Empty challenge; cannot verify login status")
			log.Println(err)
			jsonResponse(w, err.Error(), http.StatusBadRequest)
			return
		}
		
		
		// Load the user from the database and store it in the request context
		/*
		if id, ok := session.Values["user_id"]; ok {
			u, err := models.GetUser(id.(uint))
			if err != nil {
				r = r.WithContext(context.WithValue(r.Context(), "user", nil))
			} else {
				r = r.WithContext(context.WithValue(r.Context(), "user", u))
			}
		} else {
			r = r.WithContext(context.WithValue(r.Context(), "user", nil))
		}
		*/
		
		//retrieve the user from the session info
		user, err := userDB.GetUserByID(session.GetUserID())
		if err != nil {
			jsonResponse(w, err.Error(), http.StatusBadRequest)
			return
			//r = r.WithContext(context.WithValue(r.Context(), "user", nil))
		} else {
			r = r.WithContext(context.WithValue(r.Context(), "user", user))
		}
		

		// If we have a valid user, allow access to the handler. Otherwise, error
		if u := r.Context().Value("user"); u != nil {
			next.ServeHTTP(w, r)
			return
		}
		//http.Redirect(w, r, "/", http.StatusUnauthorized)
		//jsonResponse(w, "Not logged in", http.StatusUnauthorized)
		http.Error(w, "Not logged in", http.StatusUnauthorized)
		//fmt.Fprint(w, "You are not logged in")
	})
}

func Logout(w http.ResponseWriter, r *http.Request)  {
	err := sessionStore.DeleteWebauthnSession("authentication", r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	
	fmt.Fprintf(w, "Successfully logged out; redirecting to home")
	time.Sleep(time.Duration(3)*time.Second)
	http.Redirect(w, r, "/", http.StatusFound)
	
	/*
	session, err := sessionStore.GetWebauthnSession("authentication", r)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
	*/
	
	
	/*
	session, _ := store.Get(r, "userAuth")

    // Revoke users authentication
    session.Values["authenticated"] = false
    session.Save(r, w)
	cookie := &http.Cookie{
	    Name:   "userAuth",
	    Value:  "",
	    Path:   "/",
	    MaxAge: -1,
		Expires: time.Unix(0, 0),
	}
	http.SetCookie(w, cookie)
	
	jsonResponse(w, "Logged out", http.StatusOK)
	*/
}

// from: https://github.com/duo-labs/webauthn.io/blob/3f03b482d21476f6b9fb82b2bf1458ff61a61d41/server/response.go#L15
func jsonResponse(w http.ResponseWriter, d interface{}, c int) {
	dj, err := json.Marshal(d)
	if err != nil {
		http.Error(w, "Error creating JSON response", http.StatusInternalServerError)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(c)
	fmt.Fprintf(w, "%s", dj)
}

func errorResponse(w http.ResponseWriter, d interface{}, c int) {
	w.WriteHeader(c)
	fmt.Fprintf(w, "%s", d)
}
