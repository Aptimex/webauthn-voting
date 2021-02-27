package main

import (
	"encoding/json"
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
	//r.PathPrefix("/").Handler(http.FileServer(http.Dir("./")))
	//r.HandleFunc("/", HomePage).Methods("GET")
	r.HandleFunc("/cast", LoginRequired(CastBallotPage)).Methods("GET")
	r.HandleFunc("/verify", LoginRequired(VerifyBallotPage)).Methods("GET")
	r.HandleFunc("/logout", Logout).Methods("GET")

	//Implementations of paper concepts
	r.HandleFunc("/cast/begin/{username}", BeginCast).Methods("POST")
	r.HandleFunc("/cast/finish/{username}", FinishCast).Methods("POST")
	r.HandleFunc("/verify/begin/{username}", BeginVerify).Methods("POST")
	r.HandleFunc("/verify/finish/{username}", FinishVerify).Methods("POST")
	r.HandleFunc("/void", LoginRequired(VoidBallot)).Methods("GET")
	r.HandleFunc("/status", LoginRequired(Status)).Methods("GET")

	//Debug additions
	r.HandleFunc("/dumpUsers", userDump).Methods("GET")
	r.HandleFunc("/dumpSessions", DumpSessions).Methods("GET")
	r.HandleFunc("/dumpPending", DumpPending).Methods("GET")
	r.HandleFunc("/dumpVerified", dumpVerified).Methods("GET")
	r.HandleFunc("/reverify", LoginRequired(Reverify)).Methods("GET")
	
	//Home page server
	r.PathPrefix("/").Handler(http.FileServer(http.Dir("./")))


	log.Println("starting server at", serverAddress)
	log.Fatal(http.ListenAndServe(serverAddress, r))
}

//Returns all the data associated with registered users for debugging
func userDump(w http.ResponseWriter, r *http.Request) {
	//log.Printf("%+v\n", userDB.users)
	data := userDB.DumpDB()
	jsonResponse(w, data, http.StatusOK)
}

//Not implemented on back-end since client-side secure session cookies can't be tracked by server
func DumpSessions(w http.ResponseWriter, r *http.Request) {
	//log.Printf("%+v\n", userDB.users)
	data := "Not implemented."
	jsonResponse(w, data, http.StatusOK)
}

//Returns all ballots with a "pending" status
func DumpPending(w http.ResponseWriter, r *http.Request) {
	data := ballots.DumpPending()
	//log.Println(data)
	jsonResponse(w, data, http.StatusOK)
}

//Returns all ballots with a "verified" status
func dumpVerified(w http.ResponseWriter, r *http.Request) {
	data := ballots.dumpVerified()
	//log.Println(data)
	jsonResponse(w, data, http.StatusOK)
}

//Returns all ballots with an "error" or "void" status
func DumpError(w http.ResponseWriter, r *http.Request) {
	data := ballots.DumpError()
	//log.Println(data)
	jsonResponse(w, data, http.StatusOK)
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

//Return status information for the ballot associated with the logged-in user
//Wrap this handler in the LoginRequired() hanlder
func Status(w http.ResponseWriter, r *http.Request)  {
	user, err := GetUser(r)
	if err != nil {
		log.Println(err)
		jsonResponse(w, struct {Status string; Data string}{err.Error(), ""}, http.StatusBadRequest)
		return
	}
	
	ballot, err := ballots.GetBallot(user)
	if err != nil { //only thrown if no ballot found
		jsonResponse(w, struct {Status string; Data string}{err.Error(), ""}, http.StatusOK)
		return
	}
	
	jsonResponse(w, struct {Status BallotStatus; Data string}{ballot.Status, ballot.Data}, http.StatusOK)
}

//Same as Status() but also re-verifies the current voter's ballot signatures (if any)
//Demonstrates that storing full HSK responses enables ballot signature auditing after-the-fact
//Wrap this handler in the LoginRequired() hanlder
func Reverify(w http.ResponseWriter, r *http.Request)  {
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
	
	err, msg := ballot.Verify(ballots)
	
	jsonResponse(w, struct {Status BallotStatus; Data string; Err error; Msg string}{ballot.Status, ballot.Data, err, msg}, http.StatusOK)
}

//Same as the BeginLogin handler for authentication, but sets the body contents as the Challenge
// instead of generating a random challenge
//This should retrieve the user from the included session token, but doing so via a supplied
// username instead demonstrates that even a spoofed session can't be used to cast a ballot
// without the correct HSK (but will display the ballot data)
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
	
	//See if cast ballot already exists;
	// err will only be set iff no ballot found for this user, so no need to handle errors
	ballot, _ := ballots.GetBallot(user)
	if ballot != nil { //ballot found
		errorResponse(w, "Ballot already cast for user " + username, http.StatusInternalServerError)
		return
	}

	//Same as webAuth.BeginLogin, but passes the challenge as 'data'
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

//Same as the FinishLogin handler for authentication, but also stores the ballot data
// and HSK response after verifying its validity.
//This should retrieve the user from the included session token, but doing so via a supplied
// username instead demonstrates that even a spoofed session can't be used to cast a ballot
// without the correct HSK (but will display the ballot data)
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
	
	//Same as webAuth.FinishLogin, but returns the verified data and HSK response so
	// they can be stored in the ballot structure
	_, veriData, parsedResponse, err := webAuthn.FinishCast(user, sessionData, r)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
	
	//Construct a ballot from the verified data
	err = ballots.AddBallot(user, veriData, parsedResponse)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
	
	jsonResponse(w, veriData, http.StatusOK)
}

//Similar to BeginCast; the body should contain the base64 encoding of the original ballot data
// (which was sent to the client when the Verify page was loaded). This checks that it matches
// the data in a pending ballot for this user and then uses it as the challenge in the response
//This should retrieve the user from the included session token, but doing so via a supplied
// username instead demonstrates that even a spoofed session can't be used to verify a ballot
// without the correct HSK (but will display the ballot data)
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
	
	//Get the stored ballot for this user
	pending, err := ballots.GetBallot(user)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}
	
	//Make sure the stored ballot is pending
	if pending.Status != BS_PENDING {
		status, _ := json.Marshal(pending.Status)
		err = fmt.Errorf("Ballot does not have Pending status, cannot be Verified. Status: " + string(status))
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}
	
	pendingData := pending.Data
	
	//Compare data in request to stored ballot data, make sure it matches
	if data != pendingData {
		err = fmt.Errorf("Verification data does not match pending data: \nvData: " + data + "\npData: " + pendingData)
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	//Same as webAuth.BeginLogin, but passes the challenge as 'data'
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

//Similar to FinishCast; adds the validated HSK response to the ballot struct
//This should retrieve the user from the included session token, but doing so via a supplied
// username instead demonstrates that even a spoofed session can't be used to verify a ballot
// without the correct HSK (but will display the ballot data)
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
	
	
	//webAuthn.FinishVerify() does exactly the same thing as webAuth.FinishCast(),
	// just named differently to be consistent with these libraries' conventions
	_, veriData, parsedResponse, err := webAuthn.FinishVerify(user, sessionData, r)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
	
	//store the second sig and mark as verified
	err = ballots.VerifyBallot(user, veriData, parsedResponse)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
	
	jsonResponse(w, veriData, http.StatusOK)
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

//Processes a request to void a pending ballot.
//Does not require HSK signagure, but should be wrapped in the LoginRequired() hanlder
// so that only a logged-in user can do so. Will fail anyway if no valid session is provided.
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

//Returns the current user's User struct based on session cookies in the request
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
	
	return user.name, nil
}

//Convenience wrapper for sending JSON-encoded responses
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

//Convenience wrapper for sending back error responses (without JSON encoding, for raw display)
func errorResponse(w http.ResponseWriter, d interface{}, c int) {
	w.WriteHeader(c)
	fmt.Fprintf(w, "%s", d)
}
