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

// Same as the User struct, but all the fields are public for JSON-marshalling
type UserPub struct {
	Id          uint64
	Name        string
	DisplayName string
	Credentials []webauthn.Credential `json:"creds"`
}

//JSON and other library methods can't interact with non-public fields, so this makes a usable copy
func (u User) ToPub() UserPub {
	var p UserPub
	p.Id = u.id
	p.Name = u.name
	p.DisplayName = u.displayName
	p.Credentials = u.credentials
	return p
}

//Same as ToPub but returns a pointer to the struct instead of the struct itself
func (u User) ToPubPtr() *UserPub {
	tmp := u.ToPub()
	return &tmp
}

//Converts a public struct back to private one
func (u UserPub) ToPriv() User {
	var p User
	p.id = u.Id
	p.name = u.Name
	p.displayName = u.DisplayName
	p.credentials = u.Credentials
	return p
}

//Converts a public struct back to private one and returns a pointer to it
//This will be a COPY of the original User struct; the pointer will NOT be equivalent to the original User.
func (u UserPub) ToPrivPtr() *User {
	tmp := u.ToPriv()
	return &tmp
}

//Makes a private User struct Marshal-able into JSON
func (u User) json() string {
	tmp, err := json.Marshal(u.ToPub())
	if err != nil {
		fmt.Println(err)
		return "ERROR" //make sure errors are obvious
	}
	return string(tmp)
}

//Debugging function that prints a User struct in human-redable format
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
		//Ignore Authenticator struct for now, not really needed for debugging
	}
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
