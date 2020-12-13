module github.com/Aptimex/webauthn_dual

go 1.12

replace github.com/duo-labs/webauthn => ../webauthn //github.com/Aptimex/webauthn master

replace github.com/duo-labs/webauthn.io => ../webauthn.io //github.com/Aptimex/webauthn.io master

require (
	github.com/duo-labs/webauthn v0.0.0-20191119193225-4bf9a0f776d4
	github.com/duo-labs/webauthn.io v0.0.0-20190926134215-35f44a73518f
	github.com/google/go-tpm v0.1.0 // indirect
	github.com/gorilla/mux v1.7.3
	github.com/jinzhu/gorm v1.9.11 // indirect
	gopkg.in/square/go-jose.v2 v2.2.2 // indirect
)
