# Setup
Install Golang. `git clone` this repo, webauthn, and webauthn.io into the same directory (i.e., three separate folders, one for each repo, in the same root directory). Make sure these folders are named `webauthn-voting`, `webauthn`, and `webauthn.io` respectively (should be by default).  Navigate to the webauthn-voting folder and run `go run .`. Open a WebAuthn-compatable browser and navigate to `localhost:9999`.

# Overview
This codebase (together with the webauthn and webauthn.io repos) provides an example implementation of the novel ideas presented in my Master thesis. It allows a standard WebAuthn-compatible authenticator (a Yubikey 5 series was used for testing) to be used in conjunction with two separate web sessions to demonstrate assurances against client-side malware manipulation of user-submitted data.

This is a modification to hbolimovsky's example WebAuthn implementation (used with permission), which itself relies on code from [duo's WebAuthn implementation](https://github.com/duo-labs/webauthn) and [duo's WebAuthn example implementation](https://github.com/duo-labs/webauthn.io). The code in both of duo's repos needed some small modifications as well to make this project work, so a project-specific copy of those are available too.

Much like hbolimovsky's original repo, this example is NOT meant to be used in production, but rather as proof of concept for the ideas presented in my thesis. Some features that would be critical in production but not directly related to the core novel ideas were left out for simplicity where industry-standard methods for addressing them already exist. An effort has been made to mention these omissions in the source code comments, but the paper should be used as a more comprehensive guide to what would need to be added to make this reasonably secure in a production environment.

# Basic demonstrations
This section describes at a very high level what this code demonstrates. This leaves out many important caveats and limitations which are discussed in depth in my paper.

## Basic Flow
The home page (/, index.html) allows for registration and then login. A successful login will initially redirect to the /cast page.

The Cast page (/cast, voteCast.html) asks for some input (representing the capacity for handling arbitrary data), which can be submitted with the "Cast Ballot" button. Alternatively, the "Simulate" button can be used to simulate an attempt by "advanced" malware to modify the submitted data without alerting the user. In either case, a popup will ask the user to confirm the data they are about to submit, and then they will be asked to authorize that submission using a process identical (from the user's perspective) to logging in with the registered authenticator. Once cast, the ballot enters a "pending" state, requiring verification before it is actually recorded and countable.

The Verify page (/verify, voteVerify.html) fetches the cast ballot from the server (for the current authenticated voter) and displays its contents to the voter. If the displayed ballot information is correct, the voter can use the Verify Ballot button to confirm its corretness (using the same authenticator-based process used to cast the ballot). If the displayed ballot information is not correct (i.e., does not match their original or intended submission, indicating possible manipulation) they may click the VOID Ballot button to permenantly discard their ballot.

Both the Cast and Verify pages will poll the server every 5 seconds for the status of the authenticated voter's ballot and display that information to the voter in the Current Ballot Status section. Feedback and errors about voter interactions with the server will be displayed in the Errors and Feedback section.

## Emulating and Mitigating Attacks
### Ballot Manipulation
On the Cast page, clicking the "Simulate covert ballot manipulation" button will modify the ballot data in the background (changing it to the string "Manipulated ballot data"), but continue to display the original ballot data on all on-screen messages that would normally display the manipulated data. From the voter's perspective, clicking this button will appear to do the exact same thing as clicking the Cast Ballot button. This demonstrates how stealthy computer malware could alter a ballot submission in a covert way that would be effectively undetectable to the voter.

#### Voting with one device (or malware on two devices)
If the Verify page is loaded in the same web browser instance that was used to Cast a malware-manipulated ballot, it will continue to modify the displayed ballot data to match what the voter submitted, while using the manipulated data in the background. This demonstrates the danger of using the same device to Cast and Verify a ballot (or different devices with the same malware working in concert), since client-side malware will have an easy time manipulating displayed data at all stages and prevent the voter from seeing those manipulations.

The following sections describe how this scheme will succesfully ensure that malware present on only one of the voter's two devices will be either prevented from modifying a ballot, or discovered by the diligent voter. Note that it requires the voter to be able to see the screens of both devices throughout the process to be fully effective, and assumes the voter will treat any discrepencies between the two as evidence of manipulation.

#### Malware on only the casting device
Loading the Verify page in different browser instance (than the instance used to cast the ballot) represents the real-world equivalent of loading it on a different malware-free device (since it's really inconvenient to use an actual separate device in this demo environment). Doing so will prevent the malware-emulator code from running, and thus the ballot data manipulated on the first device will be discovered when it is displayed to the voter. The voter will then be able to click the VOID Ballot button to discard their manipulated ballot.

#### Malware on only the verifying device
Loading the Verify page with the paramter "auto" included in the url (e.g., `localhost:9999/verify?auto`) will cause a different malware emulation on that page to run. It will inspect the returned ballot data and check if it matches the string "Desirable ballot". This represents an arbitrary "desirable" vote that the malware wants to ensure is verified, hoping that some voters will accidently submit the wrong selection that it can force them to verify. This malware will display a fake login error and ask the voter to log in again, but actually use their authenticator authorization for the "login" to verify the desirable ballot data.

Alternatively, if the ballot does not contain that string, the malware will automatically void the ballot before it even gets displayed to the voter. In both these cases the malware makes no attempt to hide its action after it accomplishes its goal. But even if it did the voter would still see the updated ballot status ("verified" or "void") on the screen of their first (malware-free) device that they used to cast their ballot and be alerted to the manipulation.

### Remediation
In all cases where the voter detects a manipulation attempt, they need to have some way of remediating it (since this example provides no recourse beyond voiding a manipulated ballot). A real-world remediation model that prevents abuse by remote attackers or client-side malware requires careful consideration of several factors, and is discussed in the paper. Proper treatment of this topic cannot be given here.


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
    
