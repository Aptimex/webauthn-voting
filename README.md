# Begin working notes

# Setting Up
In VMWare, go to VM->Settings->Options->Shared Folders. Disable, OK, Enable, OK. Link doesn't persist across reboots for some reason.

Use link to go to git/webauthn_dual. Then `go run .`

## Access from Host
To port forward (only needed once) go to Edit->Virtual Network Editor. Select NAT->NAT Settings->Add. Forward <IP>:8080 to a host port, where <IP> is the guest IP (`ip a`). Should now be accessible from host.

## Enable private repos for go get
https://stackoverflow.com/questions/27500861/whats-the-proper-way-to-go-get-a-private-repository

`git config --global url.git@github.com:.insteadOf https://github.com/`

`export GOPRIVATE=github.com/Aptimex`

## Other useful stuff
Copy a repo so you can make it private: https://docs.github.com/en/free-pro-team@latest/github/creating-cloning-and-archiving-repositories/duplicating-a-repository

Remove a package installed with `go get`: https://stackoverflow.com/questions/13792254/removing-packages-installed-with-go-get

Deploy keys can only be used once; https://docs.github.com/en/free-pro-team@latest/developers/overview/managing-deploy-keys#deploy-keys and   https://unix.stackexchange.com/questions/322124/ssh-add-add-all-private-keys-in-ssh-directory
- Would actually have to do this, which is more work than it's worth; just use site-wide key: https://gist.github.com/gubatron/d96594d982c5043be6d4

To get replacement repo, use replace github.com/duo-labs/webauthn => github.com/Aptimex/webauthn master
- Don't modify import names in any other files; this is functionally a global find+replace

# End working notes

# Setup
Install Golang. `git clone` this repo, webauthn, and webauthn.io into the same directory (i.e., three separate folders, one for each repo, in the same root directory). Make sure these folders are named `webauthn_dual`, `webauthn`, and `webauthn.io` respectively (should be by default).  Navigate to the webauthn_dual folder and run `go run .`. Open a WebAuthn-compatable browser and navigate to `localhost:9999`.

# Overview
This codebase (together with the webauthn and webauthn.io repos) provides an example implementation of the novel ideas presented in my Master thesis. It allows a standard WebAuthn-compatible authenticator (a Yubikey 5 series was used for testing) to be used in conjunction with two separate web sessions to demonstrate assurances against client-side malware manipulation of user-submitted data.

This is a modification to hbolimovsky's example WebAuthn implementation (used with permission), which itself relies on code from [duo's WebAuthn implementation](https://github.com/duo-labs/webauthn) and [duo's WebAuthn example implementation](https://github.com/duo-labs/webauthn.io). The code in both of duo's repos needed some small modifications as well to make this project work, so a project-specific copy of those are available too.

Much like hbolimovsky's original repo, this example is NOT meant to be used in production, but rather as proof of concept for the ideas presented in my thesis. Some features that would be critical in production but not directly related to the core novel ideas were left out for simplicity where industry-standard methods for addressing them already exist. An effort has been made to mention these omissions in the source code comments, but the paper should be used as a more comprehensive guide to what would need to be added to make this reasonably secure in a production environment.

# Basic demonstrations
This section describes at a very high level what this code demonstrates. This leaves out many important caveats and limitation discussions which are discussed in depth in my paper.

## Basic Flow
The home page allows for registration and then login. A successful login will initially redirect to the /cast page.

The Cast page asks for some input (representing the capacity for handling arbitrary data), which can be submitted with the "Cast Ballot" button. Alternatively, the "Simulate" button can be used to simulate an attempt by "advanced" malware to modify the submitted data without the user being aware. In either case, a popup will ask the user to confirm the data they are about to submit, and then they will be asked to authorize that submission using a process identical (from the user's perspective) to logging in with the registered authenticator.



# Functional modifications and additions
Lines prefaced with a + indicate files that they were added, rather than modifications of existing files.

Files with modifications unrelated to the core demonstration functionality (such as tweaked debug messages) are not included in this list.

## webauthn_example
    README.md
    +ballots.go
    +debug.go
    index.html
    +logout.html
    script.js
    server.go
    +style.css
    user.go
    userdb.go
    +util.go
    +vote.go
    +voteCast.html
    +voteVerify.html

## webauthn (duo library)
    /webauthn/session.go
    /webauthn/login.go
    /webauthn/registration.go

## webauthn.io (duo example)
    /session/session.go
    
