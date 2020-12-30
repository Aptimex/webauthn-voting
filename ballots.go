package main

import (
    "fmt"
    "sync"
    "encoding/json"
    "log"
    //"net/http"
    //"io"
    
    "github.com/duo-labs/webauthn/protocol" //for the ParsedAssertionResponse struct in assertion.go
)

type Ballot struct {
    Data        string //the "challenge" in WebAuthn terms
    
    //sigData contains Response and Raw objects of type ParsedAssertionResponse and CredentialAssertionResponse respectively
    //Can run .Verify(storedChallenge string, relyingPartyID, relyingPartyOrigin string, verifyUser bool, credentialBytes []byte) on them
    //see webauthn/protocol/assertion.go for details
    SigData1    *protocol.ParsedCredentialAssertionData `json:"sig1"` //initial submission
    SigData2    *protocol.ParsedCredentialAssertionData `json:"sig2"` //verification
}

type PendingBallots struct {
	Ballots    map[*UserPub]*Ballot
    mu         sync.RWMutex
}

type CastBallots struct {
    Ballots    map[*UserPub]*Ballot
    mu         sync.RWMutex
}

func CheckAlreadyVotedError(user *UserPub) error {
    if _, ok := pending.Ballots[user]; ok {
        return fmt.Errorf("Pending ballot already exists for user " + user.Name)
    }
    
    if _, ok := cast.Ballots[user]; ok {
        return fmt.Errorf("Cast ballot already exists for user " + user.Name)
    }
    
    return nil
}

func (pb *PendingBallots) AddBallot(u *User, data string, parsedResponse *protocol.ParsedCredentialAssertionData /*response *http.Request*/ /*sig *protocol.ParsedAssertionResponse*/) (err error)  {
    user := u.ToPubPtr()
    
    if user == nil {
        return fmt.Errorf("No user specified")
    }
    
    if pb == nil {
        return fmt.Errorf("Pending ballots not initialized")
    }
    //store the parsedResponse with the ballot so its sig (on `data` as the challenge) can be verified any time
    //parsedResponse, err := protocol.ParseCredentialRequestResponse(response)
    /*
    parsedResponse, err := protocol.ParseCredentialRequestResponseBody(bodyContent)
	if err != nil {
		return err
	}
    */
    
    //webauthn/protocol/assertion.go->Verify() and webauthn/protocol/webauthncose/webauthncose.go->VerifySignature()
    /*
    // Step 15. Let hash be the result of computing a hash over the cData using SHA-256.
	clientDataHash := sha256.Sum256(p.Raw.AssertionResponse.ClientDataJSON)

	// Step 16. Using the credential public key looked up in step 3, verify that sig is
	// a valid signature over the binary concatenation of authData and hash.

	sigData := append(p.Raw.AssertionResponse.AuthenticatorData, clientDataHash[:]...)

	key, err := webauthncose.ParsePublicKey(credentialBytes)

	valid, err := webauthncose.VerifySignature(key, sigData, p.Response.Signature)
	if !valid {
		return ErrAssertionSignature.WithDetails(fmt.Sprintf("Error validating the assertion signature: %+v\n", err))
	}
	return nil
    */
    
    pb.mu.Lock()
	defer pb.mu.Unlock()
    if err = CheckAlreadyVotedError(user); err != nil {
        return err
    }
    
    pb.Ballots[user] = &Ballot{}
	pb.Ballots[user].Data = data
    pb.Ballots[user].SigData1 = parsedResponse
    pb.Ballots[user].SigData2 = nil
    
    
    return nil
}

func (pb *PendingBallots) GetBallot(u *User) (b *Ballot, err error)  {
    user := u.ToPubPtr()
    
    pb.mu.Lock()
	defer pb.mu.Unlock()
    
    if b, ok := pb.Ballots[user]; ok {
        return b, nil
    }
    return nil, fmt.Errorf("No pending ballot found for user " + user.Name)
}

//Dump ballot info
func (pb *PendingBallots) DumpPending() (string) {
    log.Println(pb.Ballots)
    
	result := "{"
	for k, v := range pb.Ballots {
		tmp, _ := json.MarshalIndent(k, "", "  ")
		result += string(tmp)  + ":"

        tmp, _ = json.MarshalIndent(v, "", "  ")
		result += string(tmp) + ","
	}
	
	if result == "{" {
		return "{}"
	}
	return result[:len(result)-1] + "}"
    
}

//Dump ballot info
func (cb *CastBallots) DumpCast() (string) {
	result := "{"
	for k, v := range cb.Ballots {
        tmp, _ := json.MarshalIndent(k, "", "  ")
		result += string(tmp)  + ":"

        tmp, _ = json.MarshalIndent(v, "", "  ")
		result += string(tmp) + ","
	}
	
	if result == "{" {
		return "{}"
	}
	return result[:len(result)-1] + "}"
}
