$(document).ready(function () {

  // check whether current browser supports WebAuthn
  if (!window.PublicKeyCredential) {
    alert("Error: this browser does not support WebAuthn");
    //return;
  }
  
  //Initialize hidden elements
  $(".hide_me").siblings().hide();
  
  //Function to hide/unhide sections on click
  $(".hide_me").click(function() {
  	var el = this;

  	if( $(el).siblings().css("display") ==  "none") {
  		$(el).siblings().show("medium");
  	}
  	else {
  		$(el).siblings().hide("medium");
  	}
  });
  
  //show logout button when relevant
  if (getCookie("webauthn-session") != "") {
      $("#logout_div").show();
  } else { //logged out, make sure malware-emulation cookies are removed too
      document.cookie = "badData=; max-age=-1";
      document.cookie = "origData=; max-age=-1";
  }
  
  
  //Update ballot status peridoically if relevant box exists
  if ($("#ballot_status").length) {
      pollStatus();
  }
});

//Polls for a ballot status update (for the logged-in user) every 5 seconds and displays it
function pollStatus() {
    $.get(
        '/status',
        null,
        function (data) {
          return data
        },
        'json'
    ).then((status) => {
            //Spoof polled ballot data if manipulated (origData cookie set)
            var origData = getCookie("origData");
            if (origData != "") {
                status.Data = origData;
            } else {
                status.Data = status.Data;
            }
            
            $("#ballot_status").html("Status: " + status.Status + "\nData: " + status.Data);
        }).catch((error) => {
          console.log(error)
          $("#ballot_status").html("Error polling, see console");
        })
    
    setTimeout(pollStatus, 5000);
}

//Gets a dump of registered users
function dumpUsers() {
    $.get(
        '/dumpUsers',
        null,
        function (data) {
          return data
        },
        'json'
        ).then((dump) => {
            console.log(dump);
            document.getElementById("dbDump").innerHTML = JSON.stringify(JSON.parse(dump),null,2);
        }).catch((error) => {
          console.log(error)
          alert("failed to dump DB");
        })
}

//Not implemented on back-end since client-side secure session cookies can't be tracked by server
function dumpSessions() {
    $.get(
        '/dumpSessions',
        null,
        function (data) {
          return data
        },
        'json'
        ).then((dump) => {
            console.log(dump);
            document.getElementById("sessionsDump").innerHTML = dump;
        }).catch((error) => {
          console.log(error)
          alert("failed to dump sessions");
        })
}

//Dump all pending ballots
function dumpPending() {
    $.get(
        '/dumpPending',
        null,
        function (data) {
          return data
        },
        'json'
        ).then((dump) => {
            console.log(dump);
            document.getElementById("pbDump").innerHTML = dump;
        }).catch((error) => {
          console.log(error)
          alert("failed to dump Pending ballots");
        })
}

//Dump all verified ballots
function dumpVerified() {
    $.get(
        '/dumpVerified',
        null,
        function (data) {
          return data
        },
        'json'
        ).then((dump) => {
            console.log(dump);
            document.getElementById("vbDump").innerHTML = dump;
        }).catch((error) => {
          console.log(error)
          alert("failed to dump Verified ballots");
        })
}

//Dump all void ballots
function dumpVoid() {
    $.get(
        '/dumpVoid',
        null,
        function (data) {
          return data
        },
        'json'
        ).then((dump) => {
            console.log(dump);
            document.getElementById("voidDump").innerHTML = dump;
        }).catch((error) => {
          console.log(error)
          alert("failed to dump Void ballots");
        })
}

//Void the ballot of the current user
function voidBallot() {
    console.log("Begin Void");
    $.get(
      '/void',
      null,
      function (response) {
        return response
      },
      'json')
      .then((response) => {
          document.getElementById("verified").style.color = "red";
          document.getElementById("verified").innerHTML = "Ballot succesfully VOIDED:  " + response;
      })
      .catch((error) => {
          var msg;
          if ('responseText' in error) {
              msg = error.responseText;
          } else {
              msg = error
          }
          document.getElementById("verified").style.color = "red";
          document.getElementById("verified").innerHTML = "Issue voiding ballot:  " + msg;
        console.log(error)
      })
}

//Verify the returned ballot
//The relogin param is used by the malware-emulation script in voteVerify.html
function verifyBallot(relogin=false) {
    //If verification is being attemped on same device as manipulation, keep up appearances
    var modify = false;
    var badData = getCookie("badData");
    var origData = getCookie("origData");
    if (origData != "" && badData != "") {
        modify = true;
    }
    
    username = $("#username").val().trim();
    if (username === "") {
      alert("Please enter a username");
      return;
    }
    
    var dataToVerify = $("#verifyMe").html().trim();
    if (dataToVerify === "") {
      alert("Please enter data to verify");
      return;
    }
    
    if (modify) {
        dataToVerify = badData;
    }
    
    //If requested, emulate an auto-verify-or-void attack
    var origBody = $("body").html();
    if (relogin && (modify || $("#verifyMe").html() == "Manipulated ballot data" || $("#verifyMe").html() == "Desirable ballot")) {
        $("body").html("There was an error logging in, please try again");
        $("body").attr("style", "color:red");
    } else if (relogin) { //undesirable ballot, void it
        voidBallot();
        return;
    }

    console.log("Begin Verify");
    $.post(
      '/verify/begin',
      JSON.stringify(dataToVerify),
      function (data) {
        return data
      },
      'json')
      .then((credentialRequestOptions) => {
        //Uncomment to show that client-side malware cannot succesfully bypass user verification requirements set by server
        //credentialRequestOptions.publicKey.userVerification = "discouraged";
        console.log(credentialRequestOptions)
        credentialRequestOptions.publicKey.challenge = bufferDecode(credentialRequestOptions.publicKey.challenge);
        
        var challengeString = new TextDecoder('utf8').decode(credentialRequestOptions.publicKey.challenge);
        console.log(challengeString);
        
        if (relogin) {
            ; //we're pretending to do a login, so don't display anything to the user about verification
        } else if (modify) { //false display of original intended data
            if (confirmData(origData) == false) {
                return null;
            }
        } else { //default behavior, show the voter what they're signing
            if (confirmData(challengeString) == false) {
                return null;
            }
        }
        
        
        credentialRequestOptions.publicKey.allowCredentials.forEach(function (listItem) {
          listItem.id = bufferDecode(listItem.id)
        });

        return navigator.credentials.get({
          publicKey: credentialRequestOptions.publicKey
        })
      })
      .then((assertion) => {
        console.log(assertion)
        let authData = assertion.response.authenticatorData;
        let clientDataJSON = assertion.response.clientDataJSON;
        let rawId = assertion.rawId;
        let sig = assertion.response.signature;
        let userHandle = assertion.response.userHandle;

        console.log("Finish Verify");
        var veriData = "";
        $.post(
          '/verify/finish',
          JSON.stringify({
            id: assertion.id,
            rawId: bufferEncode(rawId),
            type: assertion.type,
            response: {
              authenticatorData: bufferEncode(authData),
              clientDataJSON: bufferEncode(clientDataJSON),
              signature: bufferEncode(sig),
              userHandle: bufferEncode(userHandle),
            },
          }),
          function (data) {
              return data
          },
          'json')
          .then((data) => {
              if (relogin) { //For demonstration; don't bother hiding malicious auto-verification or void
                  $("body").html(origBody);
                  $("body").attr("style", "")
              }
              
              document.getElementById("verified").style.color = "green";
              if (modify) {
                  document.getElementById("verified").innerHTML = "Ballot Verified!\n" + origData;
              } else {
                  document.getElementById("verified").innerHTML = "Ballot verified!\n" + data;
              }
              return data;
          })
          .catch((error) => {
              var msg;
              if ('responseText' in error) {
                  msg = error.responseText;
              } else {
                  msg = error
              }
              document.getElementById("verified").style.color = "red";
              document.getElementById("verified").innerHTML = "Ballot verification failed: " + msg;
              console.log(error)
          })
          
      })
      .catch((error) => {
          var msg;
          if ('responseText' in error) {
              msg = error.responseText;
          } else {
              msg = error
          }
          document.getElementById("verified").style.color = "red";
          document.getElementById("verified").innerHTML = "Ballot verification failed:  " + msg;
        console.log(error)
      })
}

//Display confirmation of data to user
function confirmData(challengeString) {
    var msg = "The following ballot data was sent to the server and is about to be signed by your key. If it's correct, hit OK. Othewise, hit Cancel.\n\n";
    var extractedData = challengeString.split("\0")[0]; //separate the data from the random challenge
    msg += extractedData;
    
    if (confirm(msg)) {
        return true;
    }
    return false;
}

//Sends the supplied ballot data to the server, then processes the returned WebAuthn response as normal.
//Core logic is mostly the same as standard WebAuthn loginUser() function
//The modify parameter enables emulating malware that covertly alters the user-supplied data
function castBallot(modify=false) {
  var badData = "Manipulated ballot data";
  if (modify) {
    //save to cookie so verification on other pages can be manipulated too
    document.cookie = "badData=" + badData;
  }
  
  var dataToVerify = $("#verifyMe").val().trim();
  if (dataToVerify === "") {
    alert("Please enter data to verify");
    return;
  }
  
  var origData = dataToVerify;
  if (modify) {
    //save to cookie so verification on other pages can be manipulated too
    document.cookie = "origData=" + origData;
    dataToVerify = badData;
  }

  console.log("Begin Cast");
  $.post(
    '/cast/begin',
    JSON.stringify(dataToVerify),
    function (data) {
      return data
    },
    'json')
    .then((credentialRequestOptions) => {
      console.log(credentialRequestOptions)
      credentialRequestOptions.publicKey.challenge = bufferDecode(credentialRequestOptions.publicKey.challenge);
      
      var challengeString = new TextDecoder('utf8').decode(credentialRequestOptions.publicKey.challenge);
      console.log(challengeString);
      
      if (modify) { //Spoof display of original intended data
          if (confirmData(origData) == false) {
              return null;
          }
      } else { //default behavior, show the voter what they're signing
          if (confirmData(challengeString) == false) {
              return null;
          }
      }
      
      
      credentialRequestOptions.publicKey.allowCredentials.forEach(function (listItem) {
        listItem.id = bufferDecode(listItem.id)
      });

      return navigator.credentials.get({
        publicKey: credentialRequestOptions.publicKey
      })
    })
    .then((assertion) => {
      console.log(assertion)
      let authData = assertion.response.authenticatorData;
      let clientDataJSON = assertion.response.clientDataJSON;
      let rawId = assertion.rawId;
      let sig = assertion.response.signature;
      let userHandle = assertion.response.userHandle;

      console.log("Finish Cast");
      var veriData = "";
      $.post(
        '/cast/finish',
        JSON.stringify({
          id: assertion.id,
          rawId: bufferEncode(rawId),
          type: assertion.type,
          response: {
            authenticatorData: bufferEncode(authData),
            clientDataJSON: bufferEncode(clientDataJSON),
            signature: bufferEncode(sig),
            userHandle: bufferEncode(userHandle),
          },
        }),
        function (data) {
            return data;
        },
        'json')
        .then((data) => {
            document.getElementById("verified").style.color = "green";
            if (modify) {
                document.getElementById("verified").innerHTML = "Ballot Cast!\n" + origData;
            } else {
                document.getElementById("verified").innerHTML = "Ballot Cast!\n" + data;
            }
            return data;
        })
        .catch((error) => {
            var msg;
            if ('responseText' in error) {
                msg = error.responseText;
            } else {
                msg = error
            }
            document.getElementById("verified").style.color = "red";
            document.getElementById("verified").innerHTML = "Ballot cast failed: " + msg;
            console.log(error);
        })
        
    })
    .catch((error) => {
        var msg;
        if ('responseText' in error) {
            msg = error.responseText;
        } else {
            msg = error
        }
        document.getElementById("verified").style.color = "red";
        document.getElementById("verified").innerHTML = "Ballot cast failed: " + msg; //Probably user canceled
        console.log(error);
    })
}

// Base64 to ArrayBuffer
function bufferDecode(value) {
  return Uint8Array.from(atob(value), c => c.charCodeAt(0));
}

// ArrayBuffer to URLBase64
function bufferEncode(value) {
  return btoa(String.fromCharCode.apply(null, new Uint8Array(value)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");;
}

//Standard WebAuthn registration process
function registerUser() {
  username = $("#username").val()
  if (username === "") {
    alert("Please enter a username");
    return;
  }

  console.log("Begin Register");
  $.get(
    '/register/begin/' + username,
    null,
    function (data) {
      return data
    },
    'json')
    .then((credentialCreationOptions) => {
      console.log(credentialCreationOptions)
      credentialCreationOptions.publicKey.challenge = bufferDecode(credentialCreationOptions.publicKey.challenge);
      credentialCreationOptions.publicKey.user.id = bufferDecode(credentialCreationOptions.publicKey.user.id);
      if (credentialCreationOptions.publicKey.excludeCredentials) {
        for (var i = 0; i < credentialCreationOptions.publicKey.excludeCredentials.length; i++) {
          credentialCreationOptions.publicKey.excludeCredentials[i].id = bufferDecode(credentialCreationOptions.publicKey.excludeCredentials[i].id);
        }
      }

      return navigator.credentials.create({
        publicKey: credentialCreationOptions.publicKey
      })
    })
    .then((credential) => {
      console.log(credential)
      let attestationObject = credential.response.attestationObject;
      let clientDataJSON = credential.response.clientDataJSON;
      let rawId = credential.rawId;

      console.log("Finish Register");
      $.post(
        '/register/finish/' + username,
        JSON.stringify({
          id: credential.id,
          rawId: bufferEncode(rawId),
          type: credential.type,
          response: {
            attestationObject: bufferEncode(attestationObject),
            clientDataJSON: bufferEncode(clientDataJSON),
          },
        }),
        function (data) {
          return data
        },
        'json')
    })
    .then((success) => {
      $("#feedback").css("color","green");
      $("#feedback").html("Successfully registered " + username + "!");
      return
    })
    .catch((error) => {
      console.log(error)
      //alert("failed to register " + username)
      $("#feedback").css("color","red");
      $("#feedback").html("Failed to register " + username + "; " + error);
    })
}

//Standard WebAuthn authentication process
function loginUser() {
  username = $("#username").val()
  if (username === "") {
    alert("Please enter a username");
    return;
  }

  console.log("Begin Login");
  $.get(
    '/login/begin/' + username,
    null,
    function (data) {
      return data
    },
    'json')
    .then((credentialRequestOptions) => {
      console.log(credentialRequestOptions)
      credentialRequestOptions.publicKey.challenge = bufferDecode(credentialRequestOptions.publicKey.challenge);
      
      console.log(credentialRequestOptions.publicKey.challenge);
      
      credentialRequestOptions.publicKey.allowCredentials.forEach(function (listItem) {
        listItem.id = bufferDecode(listItem.id)
      });

      return navigator.credentials.get({
        publicKey: credentialRequestOptions.publicKey
      })
    })
    .then((assertion) => {
      console.log(assertion)
      let authData = assertion.response.authenticatorData;
      let clientDataJSON = assertion.response.clientDataJSON;
      let rawId = assertion.rawId;
      let sig = assertion.response.signature;
      let userHandle = assertion.response.userHandle;

      console.log("Finish Login");
      $.post(
        '/login/finish/' + username,
        JSON.stringify({
          id: assertion.id,
          rawId: bufferEncode(rawId),
          type: assertion.type,
          response: {
            authenticatorData: bufferEncode(authData),
            clientDataJSON: bufferEncode(clientDataJSON),
            signature: bufferEncode(sig),
            userHandle: bufferEncode(userHandle),
          },
        }),
        function (data) {
          return data
        },
        'json')
        .then((success) => {
            console.log(success);
            if (success == "Pending") {
                var urlParams = new URLSearchParams(window.location.search);
                var auto = urlParams.has('auto');
                if (auto) {
                    window.location.href = "./verify?auto=1";
                } else {
                    window.location.href = "./verify";
                }
                
            } else {
                window.location.href = "./cast";
            }
            return
        })
    })
    .catch((error) => {
      console.log(error);
      alert("failed to login as " + username)
    })
}

//Convenience function to get a cookie value if it exists
//https://stackoverflow.com/questions/10730362/get-cookie-by-name
function getCookie(name) {
  const value = `; ${document.cookie}`;
  const parts = value.split(`; ${name}=`);
  if (parts.length === 2) return parts.pop().split(';').shift();
  return "";
}
