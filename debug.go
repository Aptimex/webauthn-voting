package main

import (
    "net/http"
)

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
func DumpVerified(w http.ResponseWriter, r *http.Request) {
	data := ballots.DumpVerified()
	//log.Println(data)
	jsonResponse(w, data, http.StatusOK)
}

//Returns all ballots with an "error" or "void" status
func DumpVoid(w http.ResponseWriter, r *http.Request) {
	data := ballots.DumpVoid()
	//log.Println(data)
	jsonResponse(w, data, http.StatusOK)
}
