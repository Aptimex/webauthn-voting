/* Implementations for ballot-related features */

package main

import (
    "fmt"
    "sync"
    "encoding/json"
    "encoding/base64"
    "log"
    "bytes"
    
    "github.com/duo-labs/webauthn/protocol" //need the the ParsedAssertionResponse struct in assertion.go
)

//Store ballots mapped to users;
// user struct is map key so each user can only have one ballot associated with them
type BallotBox struct {
	Ballots    map[*UserPub]*Ballot
    mu         sync.RWMutex
}

//Contains the ballot contents (data) plus metadata to enable proper recording and auditing
type Ballot struct {
    VoterID     uint64 //matches user.id
    Data        string //the submitted ballot contents
    Status      BallotStatus
    
    //sigDataX contains Response and Raw objects of type ParsedAssertionResponse and CredentialAssertionResponse, respectively
    //Can re-run .Verify(storedChallenge string, relyingPartyID, relyingPartyOrigin string, verifyUser bool, credentialBytes []byte) method on them
    //see webauthn/protocol/assertion.go for details
    CastSig    *protocol.ParsedCredentialAssertionData //`json:"castSig"` //initial submission
    VerifySig    *protocol.ParsedCredentialAssertionData //`json:"verifySig"` //verification
}

//Allows explicitely marking ballot status for convenience;
// status can be verified based on the actual contents of the Ballot struct
type BallotStatus int
const (
    BS_ERROR = iota
    BS_PENDING
    BS_VERIFIED
    BS_VOID
)

//Mapping for BallotStatus to be JSON-marshaled into readable strings
var BStoString = map[BallotStatus]string {
    BS_ERROR: "Error",
    BS_PENDING: "Pending",
    BS_VERIFIED: "Verified",
    BS_VOID: "Voided",
}

//Allow BallotStatus to be JSON-marshaled into readable strings
func (bs BallotStatus) MarshalJSON() ([]byte, error)  {
    buffer := bytes.NewBufferString(`"` + BStoString[bs] + `"`)
	return buffer.Bytes(), nil
}


//Check that the ballot signatures are valid based on the linked user's first (only) credential
//Used to re-verify the validity of a ballot after it's gone through the Cast and Verify stages;
// would be useful for implementing an automated audit of all ballots
func (b *Ballot) Verify(bb *BallotBox) (error, string) {
    result := ""
    var user *UserPub = nil
    
    //Find the user associated with this ballot in a specified BallotBox;
    //To be extra robust, we should also ensure no duplicates of this ballot pointer exist for
    // other users, but this just returns the first match found
    for u, bal := range bb.Ballots {
        //Pointer comparison makes sure we're not matching a copy of the ballot struct;
        if b == bal && b.VoterID == u.Id {
            //ID comparison double checks that the ballot is really linked to this user
            if b.VoterID != u.Id {
                result := "ID mismatch between ballot and associated user in the BallotBox, cannot verify\n"
                return fmt.Errorf(result), result
            }
            
            user = u
            break
        }
    }
    if user == nil {
        result := "Ballot isn't mapped to a registered user in the BallotBox, cannot verify\n"
        return fmt.Errorf(result), result
    }
    
    data := b.Data
    
    config := webAuthn.Config
    if b.CastSig != nil {
        challenge1 := b.CastSig.Response.CollectedClientData.Challenge
        tmp, err := base64.RawURLEncoding.DecodeString(challenge1)
        if err != nil {
            return err, result + err.Error()
        }
        
        //Make sure challenge1 data matches ballot data
        data1 := string(bytes.Split(tmp, []byte{0})[0]) //extract the data from the challenge
        if data != data1 {
            result += "Data and data1 don't match: " + data + "; " + data1 + " \n"
            return fmt.Errorf(result), result
        }
        
        //Data check was performed above; passing duplicate challenge1 is fine, just need to check the signature
        err = b.CastSig.Verify(challenge1, config.RPID, config.RPOrigin, true, user.Credentials[0].PublicKey)
        if err != nil {return err, ""}
        result += "1st sig valid\n"
        
        //Only check VerifySig stuff if CastSig checked out
        if b.VerifySig != nil {
            challenge2 := b.VerifySig.Response.CollectedClientData.Challenge
            
            //Detect replay attacks
            if challenge1 == challenge2 {
                result += "Both challenges are identtical; VERY likely a replay attack\n"
                return fmt.Errorf(result), result
            }
            
            tmp, err = base64.RawURLEncoding.DecodeString(challenge2)
            if err != nil {
                return err, result + err.Error()
            }
            
            //Make sure challenge2 data matches ballot data
            data2 := string(bytes.Split(tmp, []byte{0})[0])
            if data != data2 {
                result += "Data and data2 don't match: " + data + "; " + data2 + " \n"
                return fmt.Errorf(result), result
            }
            //Data check was performed above; passing duplicate challenge2 is fine, just need to check the signature
            err := b.VerifySig.Verify(challenge2, config.RPID, config.RPOrigin, true, user.Credentials[0].PublicKey)
            if err != nil {return err, ""}
            result += "2nd sig valid\n"
            
            
        }
    }
    
    return nil, result
}

//Checks if a specific user has already cast a ballot in this box, and returns the status is if so.
func (bb *BallotBox) AlreadyVoted(user *UserPub) (bool, error) {
    for u, b := range bb.Ballots {
        if u.Id == user.Id {
            if b.Status == BS_VOID {
                return true, fmt.Errorf("Voided ballot already exists for user " + user.Name)
            }
            
            if b.Status == BS_ERROR {
                return true, fmt.Errorf("Uninitialized or malformed ballot already exists for user " + user.Name)
            } else if b.Status == BS_PENDING {
                return true, fmt.Errorf("Pending Ballot already exists for user " + user.Name)
            } else if b.Status == BS_VERIFIED {
                return true, fmt.Errorf("Cast Ballot already exists for user " + user.Name)
            } else {
                return true, fmt.Errorf("Ballot in known state already exists for user " + user.Name)
            }
        }
    }
    
    return false, nil
}

//Creates a ballot from data submited by a user on the /cast page and stores it in the box
//VerifySig should have been validated by WebAuthn protocols before this is called; this just blindly stores whatever it's given
func (bb *BallotBox) AddBallot(u *User, data string, parsedResponse *protocol.ParsedCredentialAssertionData) (err error)  {
    user := u.ToPubPtr()
    
    if user == nil {
        return fmt.Errorf("No user specified")
    }
    
    if bb == nil {
        return fmt.Errorf("Ballot Box not initialized")
    }
    
    bb.mu.Lock()
	defer bb.mu.Unlock()
    if voted, err := bb.AlreadyVoted(user); voted {
        return err
    }
    
    bb.Ballots[user] = &Ballot{}
    bb.Ballots[user].VoterID = user.Id
	bb.Ballots[user].Data = data
    bb.Ballots[user].CastSig = parsedResponse
    bb.Ballots[user].VerifySig = nil
    bb.Ballots[user].Status = BS_PENDING
    
    return nil
}

//Adds verification data (from the /verify page) to an existing ballot
//VerifySig should have been validated by WebAuthn protocols before this is called
//This will call Verify() perform a full re-verification of the entire ballot;
// if anything is amiss, verification will fail with a descriptive error msg
func (bb *BallotBox) VerifyBallot(u *User, data string, parsedResponse *protocol.ParsedCredentialAssertionData) (err error)  {
    if bb == nil {
        return fmt.Errorf("Ballot Box not initialized")
    }
    
    user := bb.GetUserPub(u)
    if user == nil {
        return fmt.Errorf("No user specified, or no ballot found for user")
    }
    
    //Make sure ballot is in Pending status
	pending, err := bb.GetBallot(u)
	if err != nil {
		return err
	}
    
    if pending.Status != BS_PENDING {
        status, _ := json.Marshal(pending.Status)
		err = fmt.Errorf("Ballot does not have Pending status, cannot be Verified. Status: " + string(status))
		return err
	}
    if pending.VerifySig != nil { //make sure the Pending status is consistent with ballot contents
        err = fmt.Errorf("Ballot is marked as Pending, but already contains verification data.")
		return err
        //in reality this should be flagged for review since it should never happen
    }
    
    bb.mu.Lock()
	defer bb.mu.Unlock()
    
    bb.Ballots[user].VerifySig = parsedResponse
    
    err, msg := bb.Ballots[user].Verify(bb)
    if err != nil {
        //Revert verification data if comprehensive check fails
        bb.Ballots[user].VerifySig = nil
        
        err = fmt.Errorf("Unable to validate completed ballot: " + msg + "\n")
        return err
    }
    
    bb.Ballots[user].Status = BS_VERIFIED
    return nil
}

//Returns the ballot associated with the specified user, or nil if none is found.
func (bb *BallotBox) GetBallot(u *User) (b *Ballot, err error)  {
    user := u.ToPubPtr()
    
    bb.mu.Lock()
	defer bb.mu.Unlock()
    
    for usr, b := range bb.Ballots {
        if usr.Id == user.Id {
            return b, nil
        }
    }
    
    return nil, fmt.Errorf("No ballot found for user " + user.Name)
}

//Marks the ballot associated with the specified user as void, as long as the ballot is not already verified
//Necessary authorization checks for using this function should to be performed before calling this
func (bb *BallotBox) VoidBallot(u *User) (err error)  {
    user :=  bb.GetUserPub(u)
    if user == nil {
        return fmt.Errorf("No user specified, or no ballot found for user")
    }
    
    b, err := bb.GetBallot(u)
    if err != nil {
        return err
    }
    
    //can't void after already verified; follow standard provisional voting procedure to override if needed
    if b.Status == BS_VERIFIED {
        return fmt.Errorf("Cannot void, ballot is already verified")
    }
    if b.CastSig != nil && b.VerifySig != nil { //catch any verified ballots that didn't get properly marked
        return fmt.Errorf("Ballot status is " + BStoString[b.Status] + ", but contains verification data. Cannot void.")
        //in reality this should be flagged for review since it should never happen
    }
    
    bb.mu.Lock()
	defer bb.mu.Unlock()
    bb.Ballots[user].Status = BS_VOID
    
    return nil
    
}

//Dump all ballots as json
func (bb *BallotBox) DumpAll() (string) {
    //directly dump them on the server interface too
    log.Println(bb.Ballots)
    
    //kind of wonky contruction, but necessary to make output work nicely with the frontend JS
	result := "{"
	for k, v := range bb.Ballots {
		tmp, _ := json.MarshalIndent(k, "", "  ")
		result += string(tmp)  + ":"

        tmp, _ = json.MarshalIndent(v, "", "  ")
		result += string(tmp) + ","
	}
	
	if result == "{" { //make sure an empty box is still valid JSON
		return "{}"
	}
	return result[:len(result)-1] + "}" //replace the last ','
}

//Dump pending ballots as json
func (bb *BallotBox) DumpPending() (string) {
	result := "{"
	for u, b := range bb.Ballots {
        if b.Status == BS_PENDING {
            tmp, _ := json.MarshalIndent(u, "", "  ")
    		result += string(tmp)  + ":"

            tmp, _ = json.MarshalIndent(b, "", "  ")
    		result += string(tmp) + ","
        }
	}
	
	if result == "{" {
		return "{}"
	}
	return result[:len(result)-1] + "}"
}

//Dump verified ballots as json
func (bb *BallotBox) DumpVerified() (string) {
	result := "{"
	for u, b := range bb.Ballots {
        if b.Status == BS_VERIFIED {
            tmp, _ := json.MarshalIndent(u, "", "  ")
    		result += string(tmp)  + ":"

            tmp, _ = json.MarshalIndent(b, "", "  ")
    		result += string(tmp) + ","
        }
	}
	
	if result == "{" {
		return "{}"
	}
	return result[:len(result)-1] + "}"
}

//Dump voided and erroneous ballots as json
func (bb *BallotBox) DumpVoid() (string) {
	result := "{"
	for u, b := range bb.Ballots {
        if b.Status == BS_ERROR || b.Status == BS_VOID {
            tmp, _ := json.MarshalIndent(u, "", "  ")
    		result += string(tmp)  + ":"

            tmp, _ = json.MarshalIndent(b, "", "  ")
    		result += string(tmp) + ","
        }
	}
	
	if result == "{" {
		return "{}"
	}
	return result[:len(result)-1] + "}"
}

//Searches the BallotBox for the specified user; if found, returns a duplicate User struct
// with exported (public) fields so it can be JSON-marshaled correctly. If not found, returns nil
func (bb *BallotBox) GetUserPub(u *User) *UserPub {
    bb.mu.Lock()
	defer bb.mu.Unlock()
    
    for usr, _ := range bb.Ballots {
        if usr.Id == u.id {
            return usr
        }
    }
    return nil
}
