package main

import (
	"crypto/rand"
	"encoding/binary"
	
	"encoding/base64"
	"encoding/json"
	"strconv"
	"fmt"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
)

// User represents the user model
type User struct {
	id          uint64
	name        string
	displayName string
	credentials []webauthn.Credential
}

type UserPub struct {
	Id          uint64
	Name        string
	DisplayName string
	Credentials []webauthn.Credential
}

//JSON and other method can't interact with non-public fields
func (u User) ToPub() UserPub {
	var p UserPub
	p.Id = u.id
	p.Name = u.name
	p.DisplayName = u.displayName
	p.Credentials = u.credentials
	return p
}

func (u User) json() string {
	tmp, err := json.Marshal(u.ToPub())
	if err != nil {
		fmt.Println(err)
		return "CRAP"
	}
	return string(tmp)
	
}

func (u User) Print() string {
	result := ""
	result += "id: " + strconv.FormatUint(u.id, 10) + "\n"
	result += "name: " + u.name + "\n"
	result += "displayName: " + u.displayName + "\n"
	result += "creds: "
	
	for _, v := range u.credentials  {
		result += "[ID: " + base64.StdEncoding.EncodeToString(v.ID) + ", \n"
		result += "PubKey: " + base64.StdEncoding.EncodeToString(v.PublicKey) + ", \n"
		result += "Attestation Type: " + v.AttestationType + "]"
		//Ignore Authenticator struct for now
	}
	//result += "\n"
	return result
}

// NewUser creates and returns a new User
func NewUser(name string, displayName string) *User {

	user := &User{}
	user.id = randomUint64()
	user.name = name
	user.displayName = displayName
	// user.credentials = []webauthn.Credential{}

	return user
}

func randomUint64() uint64 {
	buf := make([]byte, 8)
	rand.Read(buf)
	return binary.LittleEndian.Uint64(buf)
}

// WebAuthnID returns the user's ID
func (u User) WebAuthnID() []byte {
	buf := make([]byte, binary.MaxVarintLen64)
	binary.PutUvarint(buf, uint64(u.id))
	return buf
}

// WebAuthnName returns the user's username
func (u User) WebAuthnName() string {
	return u.name
}

// WebAuthnDisplayName returns the user's display name
func (u User) WebAuthnDisplayName() string {
	return u.displayName
}

// WebAuthnIcon is not (yet) implemented
func (u User) WebAuthnIcon() string {
	return ""
}

// AddCredential associates the credential to the user
func (u *User) AddCredential(cred webauthn.Credential) {
	u.credentials = append(u.credentials, cred)
}

// WebAuthnCredentials returns credentials owned by the user
func (u User) WebAuthnCredentials() []webauthn.Credential {
	return u.credentials
}

// CredentialExcludeList returns a CredentialDescriptor array filled
// with all the user's credentials
func (u User) CredentialExcludeList() []protocol.CredentialDescriptor {

	credentialExcludeList := []protocol.CredentialDescriptor{}
	for _, cred := range u.credentials {
		descriptor := protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: cred.ID,
		}
		credentialExcludeList = append(credentialExcludeList, descriptor)
	}

	return credentialExcludeList
}
