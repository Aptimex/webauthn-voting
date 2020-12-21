package main

import (
	"fmt"
	"sync"
	"encoding/json"
)

type userdb struct {
	users map[string]*User
	mu    sync.RWMutex
}

var db *userdb

// DB returns a userdb singleton
func DB() *userdb {

	if db == nil {
		db = &userdb{
			users: make(map[string]*User),
		}
	}

	return db
}

// GetUser returns a *User by the user's username
func (db *userdb) GetUser(name string) (*User, error) {

	db.mu.Lock()
	defer db.mu.Unlock()
	user, ok := db.users[name]
	if !ok {
		return &User{}, fmt.Errorf("error getting user '%s': does not exist", name)
	}

	return user, nil
}

// GetUser returns a *User by the user's id
func (db *userdb) GetUserByID(id uint64) (*User, error) {

	db.mu.Lock()
	defer db.mu.Unlock()
	for _, user := range db.users {
		if user.id == id {
			return user, nil
		}
	}
	return &User{}, fmt.Errorf("error getting user '%s': does not exist", id)
}

// PutUser stores a new user by the user's username
func (db *userdb) PutUser(user *User) {

	db.mu.Lock()
	defer db.mu.Unlock()
	db.users[user.name] = user
}

//Dump database info
func (db *userdb) DumpDB() (string) {
	result := "{"
	for k, v := range db.users {
		tmp, _ := json.Marshal(k)
		result += string(tmp)  + ":"

		result += v.json() + ","
	}
	
	if result == "{" {
		return "{}"
	}
	return result[:len(result)-1] + "}"
}
