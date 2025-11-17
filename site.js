// site.js — client-side keygen + base64 key handling + decrypt UI

// Helpers: base64 <-> ArrayBuffer
function ab2b64(buf) {
let binary = '';
const bytes = new Uint8Array(buf);
const len = bytes.byteLength;
for (let i = 0; i < len; i++) binary += String.fromCharCode(bytes[i]);
return btoa(binary);
}

function b642ab(b64) {
const binary = atob(b64);
const len = binary.length;
const bytes = new Uint8Array(len);
for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
return bytes.buffer;
}

// Export SPKI/PKCS8 to base64
async function spkiToB64(spki) {
return ab2b64(spki);
}

async function pkcs8ToB64(pkcs8) {
return ab2b64(pkcs8);
}

// Import PKCS8 from base64 private key

async function importPrivateKeyFromB64(keyB64) {
const ab = b642ab(keyB64);
return await window.crypto.subtle.importKey(
'pkcs8',
ab,
{ name: 'RSA-OAEP', hash: 'SHA-256' },
false,
['decrypt']
);
}

// Generate RSA key pair
async function generateKeyPair() {
try {
const keyPair = await window.crypto.subtle.generateKey(
{
name: "RSA-OAEP",
modulusLength: 2048,
publicExponent: new Uint8Array([1, 0, 1]),
hash: "SHA-256",
},
true,
["encrypt", "decrypt"]
);

const publicKey = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);
const privateKey = await window.crypto.subtle.exportKey("pkcs8", keyPair.privateKey);

const publicB64 = await spkiToB64(publicKey);
const privateB64 = await pkcs8ToB64(privateKey);


document.getElementById("publicKeyOutput").value = publicB64;
document.getElementById("privateKeyOutput").value = privateB64;
} catch (err) {
alert("Error generating keys: " + err);
}
}

// Decrypt assignment
async function decryptAssignment() {
try {
const selectedName = document.getElementById("nameSelect").value;
const privateKeyB64 = document.getElementById("privateKey").value;
const resultDiv = document.getElementById("result");

if (!selectedName) {
resultDiv.innerHTML = '<p style="color: red;">Please select your name</p>';
return;
}

if (!privateKeyB64.trim()) {
resultDiv.innerHTML = '<p style="color: red;">Please paste your private key</p>';
return;
}

// Import the private key
const privateKey = await importPrivateKeyFromB64(privateKeyB64);

// Fetch encrypted assignments
const response = await fetch('encrypted_assignments.json');
if (!response.ok) {
resultDiv.innerHTML = '<p style="color: red;">Encrypted assignments file not found. Please ask the organizer to run encrypt_assignments.py</p>';
return;
}

const encryptedAssignments = await response.json();

const encryptedAssignment = encryptedAssignments[selectedName];
if (!encryptedAssignment) {
resultDiv.innerHTML = '<p style="color: red;">No assignment found for ' + selectedName + '</p>';
return;
}

// Decrypt the assignment
const decrypted = await window.crypto.subtle.decrypt(
'RSA-OAEP',
privateKey,
b642ab(encryptedAssignment)
);

// Convert decrypted bytes to string
const decoder = new TextDecoder();
const assignment = decoder.decode(decrypted);

resultDiv.innerHTML = '<p style="color: green;"><strong>Your assignment:</strong></p><p style="font-size: 1.2em; font-weight: bold;">' + assignment + '</p>';
} catch (err) {
document.getElementById("result").innerHTML = '<p style="color: red;">Error: ' + err.message + '</p>';
}
}

// Attach button click handlers
document.getElementById("decryptBtn").addEventListener("click", async () => {
    await decryptAssignment();
});

document.getElementById("genBtn").addEventListener("click", async () => {
    await generateKeyPair();
});
