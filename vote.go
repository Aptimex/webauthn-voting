package main

import (
    "net/http"
    "encoding/json"
    "log"
    "fmt"
)

//Same as the BeginLogin handler for authentication, but sets the body contents as the Challenge
// instead of generating a random challenge
func BeginCast(w http.ResponseWriter, r *http.Request) {
    user, err := GetUser(r)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
	
	var data string
	err = json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
	}
    if data == "" {
        jsonResponse(w, "Ballot data is empty, cannot cast", http.StatusBadRequest)
    }
	
	//See if cast ballot already exists;
	// err will only be set iff no ballot found for this user, so no need to handle errors
	ballot, _ := ballots.GetBallot(user)
	if ballot != nil { //ballot found
		errorResponse(w, "Ballot already cast for user " + user.name, http.StatusInternalServerError)
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
func FinishCast(w http.ResponseWriter, r *http.Request) {
    user, err := GetUser(r)
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
func BeginVerify(w http.ResponseWriter, r *http.Request) {
    user, err := GetUser(r)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
	
	var data string
	err = json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
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

	//webAuthn.BeginVerify() does exactly the same thing as webAuth.BeginCast(),
	// just named differently to be consistent with these libraries' conventions
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
func FinishVerify(w http.ResponseWriter, r *http.Request) {
    user, err := GetUser(r)
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
