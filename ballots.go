package main

import (
    "fmt"
    "crypto/sha256"
)

type Ballot struct {
    data        string
    sig1        []byte
    sig2        []byte
}

type PendingBallots struct {
	Ballots    map[*User]Ballot
    mu         sync.RWMutex
}

type CastBallots struct {
    Ballots    map[*User]Ballot
    mu         sync.RWMutex
}

var pending PendingBallots
var cast CastBallots

//automatically runs when file is loaded
func init() {
    pending.Ballots = make(map[*User]Ballot)
    cast.Ballots = make(map[*User]Ballot)
}

func CheckAlreadyVotedError(user *User) error {
    if b, ok := pending.Ballots[user]; !ok {
        return fmt.Errorf("Pending ballot already exists for user " + user.name)
    }
    
    if b, ok := cast.Ballots[user]; !ok {
        return fmt.Errorf("Cast ballot already exists for user " + user.name)
    }
    
    return nil
}

func (pb *PendingBallots) AddBallot(user *User, data string, sig []byte) (err error)  {
    if user == nil {
        return fmt.Errorf("No user specified")
    }
    
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
    
	pb.Ballots[user].data = data
    pb.Ballots[user].sig1 = sig
    pb.Ballots[user].sig2 = nil
    
    return nil
}

func (pb *PendingBallots) GetBallot(user *User) (b Ballot, err error)  {
    pb.mu.Lock()
	defer pb.mu.Unlock()
    
    b, ok := pb.Ballots[user]
    if ok {
        return b, nil
    }
    return nil, fmt.Errorf("No pending ballot found for user " + user.name)
}
