import crypto from 'crypto';
import aes256 from 'aes256';

const alice = crypto.getDiffieHellman('modp15');
const bob = crypto.getDiffieHellman('modp15');

alice.generateKeys();
bob.generateKeys();

const aliceSecret = alice.computeSecret(bob.getPublicKey(), null, 'hex');
const bobSecret = bob.computeSecret(alice.getPublicKey(), null, 'hex');

console.log(aliceSecret === bobSecret);
console.log(aliceSecret);

//Elliptic curve diffie-hellman ECDH

const tata = crypto.createECDH('secp256k1');
tata.generateKeys();

const yoyo = crypto.createECDH('secp256k1');
yoyo.generateKeys();

const tataPublicKeyBase64 = tata.getPublicKey().toString('base64');
const yoyoPublicKeyBase64 = yoyo.getPublicKey().toString('base64');


const tataSharedKey = tata.computeSecret(yoyoPublicKeyBase64, 'base64', 'hex');
const yoyoSharedKey = yoyo.computeSecret(tataPublicKeyBase64, 'base64', 'hex');

console.log(tataSharedKey === yoyoSharedKey);
console.log(tataSharedKey);
console.log(yoyoSharedKey);

const message = " this is my message to you ou ou";

const encrypted = aes256.encrypt(tataSharedKey, message);
console.log("encrypted: ", encrypted);

//message  receive

const decrypted = aes256.decrypt(yoyoSharedKey, encrypted);
console.log("decrypted message: ", decrypted);


//ECDH and AES_256_GCM
// for confidentiality: Nobody without the key can read the message
//Integrity: nobody has changed the content of the message
//authenticity: the origin of the message can be verified


const MESSAGE = " wow an other private  message";

const IV = crypto.randomBytes(16);

const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(tataSharedKey, 'hex'), IV);

let encryptedMessage = cipher.update(MESSAGE, 'utf8', 'hex');

encryptedMessage += cipher.final('hex');

const auth_tag = cipher.getAuthTag().toString('hex');

console.table({
    IV: IV.toString('hex'),
    encrypted: encryptedMessage,
    auth_tag: auth_tag
})

const payload = IV.toString('hex') + encryptedMessage + auth_tag;

const payload64 = Buffer.from(payload, 'hex').toString('base64');

console.log(payload64);

// what yoyo will do

const yoyo_Payload = Buffer.from(payload64, 'base64').toString('hex');
const yoyo_iv = yoyo_Payload.substr(0, 32);
const yoyo_encrypted = yoyo_Payload.substr(32, yoyo_Payload.length - 32 - 32);
const yoyo_auth_tag = yoyo_Payload.substr(yoyo_Payload.length - 32, 32);

console.table({
    yoyo_iv,
    yoyo_encrypted,
    yoyo_auth_tag
});


try {
    //create the decipher
    const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(yoyoSharedKey, 'hex'), Buffer.from(yoyo_iv, 'hex'));

    decipher.setAuthTag(Buffer.from(yoyo_auth_tag, 'hex'));

    let decryptedMessage = decipher.update(yoyo_encrypted, 'hex', 'utf8');
    decryptedMessage += decipher.final('utf8');
    console.log("Decrypted message: ", decryptedMessage);

} catch (error) {
    console.log(error.message);
}