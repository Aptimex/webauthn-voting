package main

import (
	"fmt"
	"log"
	"net/http"
	"html/template"
	"strings"
	"context"

	"github.com/duo-labs/webauthn.io/session"
	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
	"github.com/gorilla/mux"
)

var webAuthn *webauthn.WebAuthn
var userDB *userdb
var sessionStore *session.Store

var ballots *BallotBox
var userVerif webauthn.LoginOption

//Initialize important voting structures and settings
//Automatically runs when file is loaded at runtime
func init() {
    ballots = &BallotBox{}
    ballots.Ballots = make(map[*UserPub]*Ballot)
	
	userVerif = webauthn.WithUserVerification(protocol.UserVerificationRequirement("required"))
}

func main() {

	serverAddress := ":9999"
	
	var err error
	webAuthn, err = webauthn.New(&webauthn.Config{
		RPDisplayName: "Example Voting",     // Display Name for your site
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
	
	//Standard WebAuthn Implementations
	r.HandleFunc("/register/begin/{username}", BeginRegistration).Methods("GET")
	r.HandleFunc("/register/finish/{username}", FinishRegistration).Methods("POST")
	r.HandleFunc("/login/begin/{username}", BeginLogin).Methods("GET")
	r.HandleFunc("/login/finish/{username}", FinishLogin).Methods("POST")

	//Page handlers
	r.HandleFunc("/cast", LoginRequired(CastBallotPage)).Methods("GET")
	r.HandleFunc("/verify", LoginRequired(VerifyBallotPage)).Methods("GET")
	r.HandleFunc("/logout", Logout).Methods("GET")

	//Implementations of thesis concepts (vote.go)
	r.HandleFunc("/cast/begin/{username}", BeginCast).Methods("POST")
	r.HandleFunc("/cast/finish/{username}", FinishCast).Methods("POST")
	r.HandleFunc("/verify/begin/{username}", BeginVerify).Methods("POST")
	r.HandleFunc("/verify/finish/{username}", FinishVerify).Methods("POST")
	r.HandleFunc("/void", LoginRequired(VoidBallot)).Methods("GET")
	r.HandleFunc("/status", LoginRequired(Status)).Methods("GET")
	r.HandleFunc("/reverify", LoginRequired(Reverify)).Methods("GET")

	//Debug additions (debug.go)
	r.HandleFunc("/dumpUsers", userDump).Methods("GET")
	r.HandleFunc("/dumpSessions", DumpSessions).Methods("GET")
	r.HandleFunc("/dumpPending", DumpPending).Methods("GET")
	r.HandleFunc("/dumpVerified", dumpVerified).Methods("GET")
	
	//Home page server; this must be defined last as the catch-all
	r.PathPrefix("/").Handler(http.FileServer(http.Dir("./")))


	log.Println("starting server at", serverAddress)
	log.Fatal(http.ListenAndServe(serverAddress, r))
}

//Serve the homepage (registration and login)
func HomePage(w http.ResponseWriter, r *http.Request)  {
	tmpl, _ := template.ParseFiles("index.html")
	tmpl.Execute(w, nil)
}

//Serve the Cast page
//Wrap this handler in the LoginRequired() hanlder
//In a real implememntation this should only be accessible from a non-mobile user-agent
func CastBallotPage(w http.ResponseWriter, r *http.Request)  {
	session, err := sessionStore.GetWebauthnSession("authentication", r)
	if err != nil {
		log.Println(err)
		errorResponse(w, "Cannnot retrieve webauthn session: " + err.Error(), http.StatusBadRequest)
		return
	}
	
	//retrieve the user from the session info, diplay the username
	user, err := userDB.GetUserByID(session.GetUserID())
	if err != nil {
		errorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
	username := user.name
	
	tmpl, err := template.ParseFiles("voteCast.html")
	tmpl.Execute(w, struct {Username string}{username})
}

//Serve the Verify page
//Wrap this handler in the LoginRequired() hanlder
//In a real implememntation this should only be accessible from an approved smartphone app
func VerifyBallotPage(w http.ResponseWriter, r *http.Request)  {
	session, err := sessionStore.GetWebauthnSession("authentication", r)
	if err != nil {
		log.Println(err)
		errorResponse(w, "Cannnot retrieve webauthn session: " + err.Error(), http.StatusBadRequest)
		return
	}
	
	//retrieve the user from the session info, diplay the username
	user, err := userDB.GetUserByID(session.GetUserID())
	if err != nil {
		errorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
	username := user.name
	
	//Retrieve the user's stored ballot data to verify
	//This should check the ballot status and display an error if it was alread verified,
	// but since the server won't let you re-verify a ballot this is good enough for
	// demonstration purposes.
	pending, err := ballots.GetBallot(user)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}
	pendingData := pending.Data
	
	tmpl, err := template.ParseFiles("voteVerify.html")
	tmpl.Execute(w, struct {Username string; BallotData string}{username, pendingData})
}

//Standard WebAuthn Registration implementation
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
	
	// Set AuthenticatorSelection options
    authSelect := protocol.AuthenticatorSelection{
		AuthenticatorAttachment: protocol.AuthenticatorAttachment("cross-platform"),
		RequireResidentKey: protocol.ResidentKeyUnrequired(),
        UserVerification: protocol.VerificationRequired,
    }

    // Require direct attestation
    conveyancePref := protocol.ConveyancePreference(protocol.PreferDirectAttestation)

	// generate PublicKeyCredentialCreationOptions, session data
	options, sessionData, err := webAuthn.BeginRegistration(
		user,
		registerOptions,
		webauthn.WithAuthenticatorSelection(authSelect),
		webauthn.WithConveyancePreference(conveyancePref),
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

//Standard WebAuthn Registration implementation
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

//Standard WebAuthn Authentication implementation
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
	

	// generate PublicKeyCredentialRequestOptions (requiring user verification), session data
	options, sessionData, err := webAuthn.BeginLogin(user, userVerif)
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

//Standard WebAuthn Authentication implementation
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
	
	//Retrieve the user's ballot data to decide which redirect to use
	ballot, err := ballots.GetBallot(user)
	if err != nil {
		jsonResponse(w, "", http.StatusOK) //no ballot found
		return
	}
	
	if ballot.Status == BS_PENDING {
		jsonResponse(w, "Pending", http.StatusOK) //pending ballot, send to verify
		return
	}
	
	//some other status, default to cast
	jsonResponse(w, "", http.StatusOK)
}

//Modified from webauthn.io source code to work with this implementation
// LoginRequired sets a context variable with the user loaded from the user ID
// stored in the session cookie
func LoginRequired(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		
		//retrieve the user from the session info
		user, err := userDB.GetUserByID(session.GetUserID())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
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
		http.Error(w, "Not logged in", http.StatusUnauthorized)
	})
}

//Basic session logout functionality- just deletes session cookies.
func Logout(w http.ResponseWriter, r *http.Request)  {
	username, err := GetUsername(r)
	if err != nil {
		log.Println(err)
	}
	
	err = sessionStore.DeleteWebauthnSession("authentication", r, w)
	if err != nil {
		if err.Error() != "error unmarshalling data" { //this error is expected if no user is logged in
			cookie := http.Cookie{
				Name: "webauthn-session",
				MaxAge: -1,
			}
			http.SetCookie(w, &cookie)
			http.Error(w, "Logout issue: " + err.Error() + "; Local session cookie deleted anyway", http.StatusInternalServerError)
			return
		}
	}
	
	tmpl, err := template.ParseFiles("logout.html")
	tmpl.Execute(w, struct {Username string}{username})
}
