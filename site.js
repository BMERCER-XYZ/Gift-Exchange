// site.js — client-side keygen + PEM handling + decrypt UI

// Helpers: PEM <-> ArrayBuffer
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

function pemEncode(b64, label) {
const wrap = b64.match(/.{1,64}/g).join('\n');
return `-----BEGIN ${label}-----\n${wrap}\n-----END ${label}-----\n`;
}

function stripPem(pem) {
return pem.replace(/-----.*?-----/g, '').replace(/\s+/g, '');
}

// Export SPKI/PKCS8 to PEM
async function spkiToPem(spki) {
const b64 = ab2b64(spki);
return pemEncode(b64, 'PUBLIC KEY');
}

async function pkcs8ToPem(pkcs8) {
const b64 = ab2b64(pkcs8);
return pemEncode(b64, 'PRIVATE KEY');
}

// Import PKCS8 PEM private key
async function importPrivateKeyFromPem(pem) {
const raw = stripPem(pem);
const ab = b642ab(raw);
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

const publicPem = convertToPem(publicKey, "PUBLIC KEY");
const privatePem = convertToPem(privateKey, "PRIVATE KEY");

document.getElementById("publicKeyOutput").value = publicPem;
document.getElementById("privateKeyOutput").value = privatePem;
} catch (err) {
alert("Error generating keys: " + err);
}
}
