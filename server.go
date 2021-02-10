package main

import (
	"encoding/json"
	//"time"
	"fmt"
	"log"
	"net/http"
	"html/template"
	"strings"
	//"io"
	"context"
	//"time"
	//"io/ioutil"
    //"bytes"
	//b64 "encoding/base64"

	"github.com/duo-labs/webauthn.io/session"
	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
	"github.com/gorilla/mux"
)

var webAuthn *webauthn.WebAuthn
var userDB *userdb
var sessionStore *session.Store
var ballots *BallotBox
//var cast *CastBallots
var userVerif webauthn.LoginOption

//automatically runs when file is loaded
func init() {
    ballots = &BallotBox{}
    //cast = &BallotBox{}
    ballots.Ballots = make(map[*UserPub]*Ballot)
    //cast.Ballots = make(map[*UserPub]*Ballot)
	
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

	r.HandleFunc("/dump", dbDump).Methods("GET")
	r.HandleFunc("/dumpSessions", DumpSessions).Methods("GET")
	r.HandleFunc("/dumpPending", DumpPending).Methods("GET")
	r.HandleFunc("/dumpCast", DumpCast).Methods("GET")
	r.HandleFunc("/logout", Logout).Methods("GET")
	r.HandleFunc("/cast/begin/{username}", BeginCast).Methods("POST")
	r.HandleFunc("/cast/finish/{username}", FinishCast).Methods("POST")
	r.HandleFunc("/verify/begin/{username}", BeginVerify).Methods("POST")
	r.HandleFunc("/verify/finish/{username}", FinishVerify).Methods("POST")
	r.HandleFunc("/vote", LoginRequired(CastBallotPage)).Methods("GET")
	r.HandleFunc("/verify", LoginRequired(VerifyBallotPage)).Methods("GET")
	r.HandleFunc("/void", LoginRequired(VoidBallot)).Methods("GET")
	r.HandleFunc("/status", LoginRequired(Status)).Methods("GET")

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

func DumpSessions(w http.ResponseWriter, r *http.Request) {
	//log.Printf("%+v\n", userDB.users)
	data := "Not implemented yet"
	jsonResponse(w, data, http.StatusOK)
}

func DumpPending(w http.ResponseWriter, r *http.Request) {
	//log.Printf("%+v\n", userDB.users)
	data := ballots.DumpPending()
	log.Println(data)
	jsonResponse(w, data, http.StatusOK)
}

func DumpCast(w http.ResponseWriter, r *http.Request) {
	//log.Printf("%+v\n", userDB.users)
	data := ballots.DumpCast()
	log.Println(data)
	jsonResponse(w, data, http.StatusOK)
}

func DumpError(w http.ResponseWriter, r *http.Request) {
	//log.Printf("%+v\n", userDB.users)
	data := ballots.DumpError()
	log.Println(data)
	jsonResponse(w, data, http.StatusOK)
}

func CastBallotPage(w http.ResponseWriter, r *http.Request)  {
	//wrap this handler in the LoginRequired() hanlder
	
	session, err := sessionStore.GetWebauthnSession("authentication", r)
	if err != nil {
		log.Println(err)
		errorResponse(w, "Cannnot retrieve webauthn session: " + err.Error(), http.StatusBadRequest)
		return
	}
	
	//retrieve the user from the session info
	user, err := userDB.GetUserByID(session.GetUserID())
	if err != nil {
		errorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
	username := user.name
	
	tmpl, err := template.ParseFiles("voteCast.html")
	tmpl.Execute(w, struct {Username string}{username})
}

func VerifyBallotPage(w http.ResponseWriter, r *http.Request)  {
	//wrap this handler in the LoginRequired() hanlder
	
	session, err := sessionStore.GetWebauthnSession("authentication", r)
	if err != nil {
		log.Println(err)
		errorResponse(w, "Cannnot retrieve webauthn session: " + err.Error(), http.StatusBadRequest)
		return
	}
	
	//retrieve the user from the session info
	user, err := userDB.GetUserByID(session.GetUserID())
	if err != nil {
		errorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
	username := user.name
	
	//Retrieve the store ballot data to verify
	pending, err := ballots.GetBallot(user)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}
	
	/* Ballot status added to page, so can still display it even if verified/voided/etc
	if pending.Status != BS_PENDING {
		status, _ := json.Marshal(pending.Status)
		err = fmt.Errorf("Ballot does not have Pending status, cannot be Verified. Status: " + string(status))
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}
	*/
	pendingData := pending.Data
	
	tmpl, err := template.ParseFiles("voteVerify.html")
	tmpl.Execute(w, struct {Username string; BallotData string}{username, pendingData})
}

func Status(w http.ResponseWriter, r *http.Request)  {
	user, err := GetUser(r)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
	
	ballot, err := ballots.GetBallot(user)
	if err != nil { //only thrown if no ballot found
		jsonResponse(w, err.Error(), http.StatusOK)
		return
	}
	
	jsonResponse(w, struct {Status BallotStatus; Data string}{ballot.Status, ballot.Data}, http.StatusOK)
}

//mostly the same as BeginLogin
func BeginCast(w http.ResponseWriter, r *http.Request) {

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
	//options, sessionData, err := webAuthn.BeginCast(user, data)
	// generate PublicKeyCredentialRequestOptions (requiring user verification), session data
	options, sessionData, err := webAuthn.BeginCast(user, data, userVerif)
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
func FinishCast(w http.ResponseWriter, r *http.Request) {
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
	

	_, veriData, parsedResponse, err := webAuthn.FinishCast(user, sessionData, r)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
	
	err = ballots.AddBallot(user, veriData, parsedResponse)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
	
	
	jsonResponse(w, veriData, http.StatusOK)
}

//Verify cast ballot in separate session
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
	
	//Compare to previous ballot data
	pending, err := ballots.GetBallot(user)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}
	
	if pending.Status != BS_PENDING {
		status, _ := json.Marshal(pending.Status)
		err = fmt.Errorf("Ballot does not have Pending status, cannot be Verified. Status: " + string(status))
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}
	
	pendingData := pending.Data
	
	if data != pendingData {
		err = fmt.Errorf("Verification data does not match pending data: \nvData: " + data + "\npData: " + pendingData)
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// generate PublicKeyCredentialRequestOptions, session data
	//options, sessionData, err := webAuthn.BeginVerify(user, data)
	// generate PublicKeyCredentialRequestOptions (requiring user verification), session data
	options, sessionData, err := webAuthn.BeginVerify(user, data, userVerif)
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

//Verify cast ballot in separate session
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
	

	//Data match was performed in the BeginVerify function
	//This just makes sure it's a valid sig on that data
	log.Println("Verifying sig")
	_, veriData, parsedResponse, err := webAuthn.FinishVerify(user, sessionData, r)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
	
	//store the second sig and mark as verified
	log.Println("Verifying ballot")
	err = ballots.VerifyBallot(user, veriData, parsedResponse)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
	
	
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

//modified from webauthn.io source code
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

func VoidBallot(w http.ResponseWriter, r *http.Request)  {
	user, err := GetUser(r)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
	
	err = ballots.VoidBallot(user)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
	
	jsonResponse(w, "Ballot voided for user " + user.name, http.StatusOK)
}

//Returns the current user's username based on cookies in the request
func GetUser(r *http.Request) (*User, error)  {
	session, err := sessionStore.GetWebauthnSession("authentication", r)
	if err != nil {
		log.Println("GetUser: error retrieving session: " + err.Error())
		return nil, err
	}
	
	//retrieve the user from the session info
	user, err := userDB.GetUserByID(session.GetUserID())
	if err != nil {
		log.Println("GetUser: error retrieving user: " + err.Error())
		return nil, err
	}
	return user, nil
}

//Returns the current user's username based on cookies in the request
func GetUsername(r *http.Request) (string, error)  {
	user, err := GetUser(r)
	if err != nil {
		return "", err
	}
	
	/*
	session, err := sessionStore.GetWebauthnSession("authentication", r)
	if err != nil {
		log.Println("GetUsername: error retrieving session: " + err.Error())
		return "", err
	}
	
	//retrieve the user from the session info
	user, err := userDB.GetUserByID(session.GetUserID())
	if err != nil {
		log.Println("GetUsername: error retrieving user: " + err.Error())
		return "", err
	}
	*/
	return user.name, nil
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
