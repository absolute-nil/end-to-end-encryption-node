const crypto = require("crypto");

// private client side of alice
const alice = crypto.createECDH('secp256k1');
alice.generateKeys()

// private client side of bob
const bob = crypto.createECDH('secp256k1');
bob.generateKeys()

// public alice to server -> to bob
const alicePublicBase64 = alice.getPublicKey().toString('base64');
// public bob to server -> to alice
const bobPublicBase64 = bob.getPublicKey().toString('base64');

// in private (client side)
const aliceSharedKey = alice.computeSecret(bobPublicBase64, 'base64', 'hex');
const bobSharedKey = bob.computeSecret(alicePublicBase64, 'base64', 'hex');

// check if shared key generated is the same
console.log(aliceSharedKey === bobSharedKey); 

console.log("alice shared key",aliceSharedKey)
console.log("bob shared key",bobSharedKey)

const MESSAGE = "this is a message from alice to bob";

// setup cipher
const IV = crypto.randomBytes(16);
const cipher = crypto.createCipheriv(
    'aes-256-gcm',
    Buffer.from(aliceSharedKey, 'hex'),
    IV
)

// encrypt message using cipher

let encrypted = cipher.update(MESSAGE, 'utf8', 'hex');
encrypted += cipher.final('hex');

// for authentication that message is from alice

const auth_tag = cipher.getAuthTag().toString('hex');

console.table({
    IV: IV.toString('hex'),
    encrypted,
    auth_tag
})

const payload = IV.toString('hex') + encrypted + auth_tag;

// message to be sent to bob via server
const payload64 = Buffer.from(payload, 'hex').toString('base64')

console.log(payload64)

// in bob client

const bob_payload = Buffer.from(payload64,'base64').toString('hex')

// extract the encrypted message auth_tag and iv
const bob_iv = bob_payload.substr(0,32);
const bob_encrypted = bob_payload.substr(32, bob_payload.length - 32 -32)
const bob_auth_tag = bob_payload.substr(bob_payload.length -32, 32);

console.table({bob_iv,bob_encrypted,bob_auth_tag})

try {
    const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        Buffer.from(bobSharedKey, 'hex'),
        Buffer.from(bob_iv, 'hex')
    )
    decipher.setAuthTag(Buffer.from(bob_auth_tag,'hex'))
    
    //decrypt the message
    let decrypted = decipher.update(bob_encrypted, 'hex', 'utf8')
    decrypted += decipher.final('utf-8');
    console.log("deciphered:",decrypted)
} catch (e) {
    console.error(e.message)
}