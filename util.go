package main

import (
    "encoding/json"
    "net/http"
    "log"
    "fmt"
)

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
