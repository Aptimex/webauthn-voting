$(document).ready(function () {

  // check whether current browser supports WebAuthn
  if (!window.PublicKeyCredential) {
    alert("Error: this browser does not support WebAuthn");
    return;
  }
});

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

  username = $("#email").val()
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
      alert("successfully registered " + username + "!")
      return
    })
    .catch((error) => {
      console.log(error)
      alert("failed to register " + username)
    })
}

function loginUser() {

  username = $("#email").val()
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
    })
    .then((success) => {
      alert("successfully logged in " + username + "!")
      return
    })
    .catch((error) => {
      console.log(error)
      alert("failed to login as " + username)
    })
}
