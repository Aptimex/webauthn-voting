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
  } else { //logged out, make sure malware cookies are removed too
      document.cookie = "badData=; max-age=-1";
      document.cookie = "origData=; max-age=-1";
  }
  
  
  //Update ballot status peridoically if relevant
  if ($("#ballot_status").length) {
      pollStatus();
  }
});

function pollStatus() {
    //alert("test");
    $.get(
        '/status',
        null,
        function (data) {
          return data
        },
        'json'
    ).then((status) => {
            //$("#ballot_status").html(JSON.stringify(status);
            
            //Spoof polled ballot data if manipulated
            var origData = getCookie("origData");
            if (origData != "") {
                status.Data = origData;
            } else {
                status.Data = atob(status.Data);
            }
            
            $("#ballot_status").html("Status: " + status.Status + "\nData: " + status.Data);
        }).catch((error) => {
          console.log(error)
          //alert("failed to get ballot status");
        })
    
    setTimeout(pollStatus, 5000);
}

function dumpDB() {
    $.get(
        '/dump',
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
            document.getElementById("sessionsDump").innerHTML = dump;//JSON.stringify(JSON.parse(dump),null,2);
        }).catch((error) => {
          console.log(error)
          alert("failed to dump sessions");
        })
}

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
            document.getElementById("pbDump").innerHTML = dump; //JSON.stringify(JSON.parse(dump),null,2);
        }).catch((error) => {
          console.log(error)
          alert("failed to dump Pending ballots");
        })
}

function dumpCast() {
    $.get(
        '/dumpCast',
        null,
        function (data) {
          return data
        },
        'json'
        ).then((dump) => {
            console.log(dump);
            document.getElementById("cbDump").innerHTML = dump; //JSON.stringify(JSON.parse(dump),null,2);
        }).catch((error) => {
          console.log(error)
          alert("failed to dump Cast ballots");
        })
}

function castBallot(modify=false, badSign=false) {
    return verifyData(modify, badSign);
}

function voidBallot() {
    /*
    username = $("#username").val()
    if (username === "") {
      alert("Please enter a username");
      return;
    }
    */

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
          document.getElementById("verified").style.color = "red";
          document.getElementById("verified").innerHTML = "Issue voiding ballot:  " + error.responseText;
        console.log(error)
      })
}

function verifyBallot(relogin=false) {
    var modify = false;
    
    //verification being attemped on same device as manipulation; keep up appearances
    var badData = getCookie("badData");
    var origData = getCookie("origData");
    if (origData != "" && badData != "") {
        modify = true;
        
        //need them in base64 for this stage
        badData = btoa(badData).replace("=", ""); //backend uses/expects no padding
        origData = btoa(origData).replace("=", "");
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
    
    var origBody = $("body").html();
    if (relogin && $("#decoded").html() == "Manipulated ballot data") {
        $("body").html("There was an error logging in, please try again");
        $("body").attr("style", "color:red");
    }

    console.log("Begin Verify");
    $.post(
      '/verify/begin/' + username,
      JSON.stringify(dataToVerify),
      function (data) {
        return data
      },
      'json')
      .then((credentialRequestOptions) => {
        //Show that client-side malware cannot succesfully bypass user verification requirements set by server
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
        } else {
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
          '/verify/finish/' + username,
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
              //console.log("Finish login data:");
              //console.log(data);
              return data
          },
          'json')
          .then((data) => {
              //alert("Verification Success for data: " + atob(data));
              if (relogin) { //surpise! Everything was verified
                  $("body").html(origBody);
                  $("body").attr("style", "")
              }
              
              document.getElementById("verified").style.color = "green";
              if (modify) {
                  document.getElementById("verified").innerHTML = "Ballot Cast!\n" + atob(origData);
              } else {
                  document.getElementById("verified").innerHTML = "Ballot verified!\n" + atob(data);
              }
              return data;
          })
          .catch((error) => {
              document.getElementById("verified").style.color = "red";
              document.getElementById("verified").innerHTML = "Ballot verification failed: " + error.responseText;
              //console.log(error.responseText)
              console.log(error)
              //alert("failed to verify data for " + username)
          })
          
      })
      .catch((error) => {
          document.getElementById("verified").style.color = "red";
          document.getElementById("verified").innerHTML = "Ballot verification failed:  " + error.responseText
        console.log(error)
      })
}

function confirmData(challengeString) {
    // https://www.pair.com/support/kb/how-to-use-jquery-to-generate-modal-pop-up-when-clicked/
    
    /*
    //appends an "active" class to .popup and .popup-content
    $(".popup-overlay, .popup-content").addClass("active");
    $("#confirmBallotData").html(challengeString);
    */
    
    //var msg = "Are you sure you want to submit the following ballot data?\n";
    var msg = "The following ballot data was sent to the server and is about to be signed by your key. If it's correct, hit OK. Othewise, hit Cancel.\n\n";
    msg += challengeString;
    
    if (confirm(msg)) {
        return true;
    }
    return false;
}

// mostly the same as loginUser
function verifyData(modify=false, badSign=false) {
  var badData = "Manipulated ballot data";
  //save to cookie so verification on other pages can be manipulated too
  if (modify) {
    document.cookie = "badData=" + badData;
  }

  //username = $("#email").val()
  username = $("#username").val().trim();
  if (username === "") {
    alert("Please enter a username");
    return;
  }
  
  var dataToVerify = $("#verifyMe").val().trim();
  if (dataToVerify === "") {
    alert("Please enter data to verify");
    return;
  }
  var origData = dataToVerify;
  if (modify) {
    document.cookie = "origData=" + origData;
  }
  
  if (modify) {
    dataToVerify = badData;
  }

  console.log("Begin Cast");
  $.post(
    '/cast/begin/' + username,
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
      
      if (modify) { //false display of original intended data
          if (confirmData(origData) == false) {
              return null;
          }
      } else {
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
        '/cast/finish/' + username,
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
            //console.log("Finish login data:");
            //console.log(data);
            return data
        },
        'json')
        .then((data) => {
            document.getElementById("verified").style.color = "green";
            if (modify) {
                document.getElementById("verified").innerHTML = "Ballot Cast!\n" + origData;
            } else {
                document.getElementById("verified").innerHTML = "Ballot Cast!\n" + atob(data);
            }
            return data;
        })
        .catch((error) => {
            document.getElementById("verified").style.color = "red";
            document.getElementById("verified").innerHTML = "Ballot cast failed: " + error.responseText;
            //console.log(error.responseText)
            console.log(error)
            //alert("failed to verify data for " + username)
        })
        
    })
    /* Pretty sure this is in the wrong spot; triggers even if /verify/finish fails
    .then((success) => {
        alert("Data verified for " + username + "!")
        return
    })
    */
    .catch((error) => {
        document.getElementById("verified").style.color = "red";
        document.getElementById("verified").innerHTML = "Ballot cast failed: " + error //Probably user canceled, or other client-side issue";
      console.log(error)
      //alert("failed to verify data for " + username)
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

function registerUser() {

  //username = $("#email").val()
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
      //alert("successfully registered " + username + "!")
      $("#feedback").css("color","green");
      $("#feedback").html("successfully registered " + username + "!");
      return
    })
    .catch((error) => {
      console.log(error)
      //alert("failed to register " + username)
      $("#feedback").css("color","red");
      $("#feedback").html("Failed to register " + username + "; " + error);
    })
}

function loginUser() {

  //username = $("#email").val()
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
                window.location.href = "./vote";
            }
            return
        })
    })
    .then((success) => {
      //alert("successfully logged in " + username + "!")
      
    })
    .catch((error) => {
      console.log(error);
      alert("failed to login as " + username)
    })
}

//https://stackoverflow.com/questions/10730362/get-cookie-by-name
function getCookie(name) {
  const value = `; ${document.cookie}`;
  const parts = value.split(`; ${name}=`);
  if (parts.length === 2) return parts.pop().split(';').shift();
  return "";
}
