package main

import (
    "fmt"
    "sync"
    "encoding/json"
    "encoding/base64"
    "log"
    "bytes"
    //"net/http"
    //"io"
    
    "github.com/duo-labs/webauthn/protocol" //for the ParsedAssertionResponse struct in assertion.go
)

type BallotStatus int

const (
    BS_ERROR = iota
    BS_PENDING
    BS_VERIFIED
    BS_VOID
)

var BStoString = map[BallotStatus]string {
    BS_ERROR: "Ballot Error",
    BS_PENDING: "Pending",
    BS_VERIFIED: "Verified",
    BS_VOID: "Ballot Voided",
}

func (bs BallotStatus) MarshalJSON() ([]byte, error)  {
    buffer := bytes.NewBufferString(`"` + BStoString[bs] + `"`)
	return buffer.Bytes(), nil
}

type Ballot struct {
    VoterID     uint64 //matches user.id
    Data        string //the "challenge" in WebAuthn terms
    
    //sigData contains Response and Raw objects of type ParsedAssertionResponse and CredentialAssertionResponse respectively
    //Can run .Verify(storedChallenge string, relyingPartyID, relyingPartyOrigin string, verifyUser bool, credentialBytes []byte) on them
    //see webauthn/protocol/assertion.go for details
    SigData1    *protocol.ParsedCredentialAssertionData `json:"castSig"` //initial submission
    SigData2    *protocol.ParsedCredentialAssertionData `json:"verifySig"` //verification
    Status      BallotStatus
}

type BallotBox struct {
	Ballots    map[*UserPub]*Ballot
    mu         sync.RWMutex
}

//Check that the ballot signatures are valid based on the linked user's first (only) credential
func (b *Ballot) Verify(bb *BallotBox) (error, string) {
    result := ""
    var user *UserPub = nil
    
    for u, _ := range bb.Ballots {
        if u.Id == b.VoterID {
            user = u
            break
        }
    }
    if user == nil {
        result := "Ballot isn't mapped to a registered user in the BallotBox, cannot verify\n"
        return fmt.Errorf(result), result
    }
    
    config := webAuthn.Config
    if b.SigData1 != nil {
        err := b.SigData1.Verify(b.Data, config.RPID, config.RPOrigin, true, user.Credentials[0].PublicKey)
        if err != nil {return err, ""}
        result += "1st sig valid\n"
        
        if b.SigData2 != nil {
            err := b.SigData2.Verify(base64.StdEncoding.EncodeToString([]byte(b.Data))/*base64.b.SigData1.Response.CollectedClientData.Challenge*/, config.RPID, config.RPOrigin, true, user.Credentials[0].PublicKey)
            if err != nil {return err, ""}
            result += "2nd sig valid\n"
        }
    }
    
    
    
    return nil, result
}

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
    bb.Ballots[user].SigData1 = parsedResponse
    bb.Ballots[user].SigData2 = nil
    bb.Ballots[user].Status = BS_PENDING
    
    return nil
}

func (bb *BallotBox) VerifyBallot(u *User, data string, parsedResponse *protocol.ParsedCredentialAssertionData) (err error)  {
    if bb == nil {
        return fmt.Errorf("Ballot Box not initialized")
    }
    
    user := bb.GetUserPub(u)
    if user == nil {
        return fmt.Errorf("No user specified, or no ballot found for user")
    }
    
    //log.Println("Getting ballot")
    //Make sure ballot is in Pending status
	pending, err := bb.GetBallot(u)
	if err != nil {
		return err
	}
    
    //log.Println("Checking Status")
    if pending.Status != BS_PENDING {
        status, _ := json.Marshal(pending.Status)
		err = fmt.Errorf("Ballot does not have Pending status, cannot be Verified. Status: " + string(status))
		return err
	}
    
    //pending.SigData2 = parsedResponse
    //pending.Status = BS_VERIFIED
    
    bb.mu.Lock()
	defer bb.mu.Unlock()
    
    //log.Println("Setting verified")
    bb.Ballots[user].SigData2 = parsedResponse
    bb.Ballots[user].Status = BS_VERIFIED
    
    return nil
}

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
    
    bb.mu.Lock()
	defer bb.mu.Unlock()
    bb.Ballots[user].Status = BS_VOID
    
    return nil
    
}

//Dump ballot info
func (bb *BallotBox) DumpAll() (string) {
    log.Println(bb.Ballots)
    
	result := "{"
	for k, v := range bb.Ballots {
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

//Dump pending ballots
func (bb *BallotBox) DumpPending() (string) {
    //log.Println(bb.Ballots)
    
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

//Dump cast ballots
func (bb *BallotBox) DumpCast() (string) {
    //log.Println(bb.Ballots)
    
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

//Dump voided and erroneous ballots
func (bb *BallotBox) DumpError() (string) {
    //log.Println(bb.Ballots)
    
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
