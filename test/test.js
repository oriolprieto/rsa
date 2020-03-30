'use strict';

//import * as Rsa from '../src/rsa';
//import * as bc from 'bigint-conversion';
const Rsa = require('../rsa.cjs');
const bc = require('bigint-conversion');
const bcu = require ('bigint-crypto-utils');

const bitLength = 32;
const message = "hi!";
const hash = "hashoooo";
let rsa = new Rsa.rsa(bitLength);
let rsaServer = new Rsa.rsa(bitLength);
console.log('Original message       : ' + message);
console.log('Original message (hex) : ' + bc.bigintToHex(bc.textToBigint(message)));

console.log("\nEncrypt/decrypt test:\n");

const publicKeys = rsaServer.keys();
const localPublicKeys = rsa.keys();
console.log("Public e key: " + publicKeys.pub_e);
console.log("Public n key: " + publicKeys.pub_n);

const messageEncrypted = rsa.encrypt(message, publicKeys.pub_e, publicKeys.pub_n);
console.log("Message encrypted: " + messageEncrypted);

const messageDecrypted = rsaServer.decrypt(messageEncrypted);
console.log("Message decrypted: " + messageDecrypted);

console.log("\nBlind signature test:\n");

// Se genera el número r aleatorio y se ciega el mensaje
const r_random = rsa.getR(publicKeys.pub_n);
console.log('Random r                   : ' + r_random.r_key);
console.log('Random inverted r          : ' + r_random.r_inv_key);
console.log('Generation attempts        : ' + r_random.attempts);
console.log('R verification             : ' + bc.bigintToHex((bc.hexToBigint(r_random.r_key) * bc.hexToBigint(r_random.r_inv_key)) % bc.hexToBigint(publicKeys.pub_n)));

const messageBlinded = rsa.blind(message, publicKeys.pub_e, publicKeys.pub_n);
console.log('Message Blinded            : ' + messageBlinded);

const messageBlindedSigned = rsaServer.blindSign(messageBlinded);
//const messageBlindedSigned = rsaServer.blindSign(bc.bigintToHex(bc.textToBigint(message)));
console.log('Message Blinded Signed     : ' + messageBlindedSigned);

const messageUnblindedSigned = rsa.unblind(messageBlindedSigned, publicKeys.pub_n);
//const messageUnblindedSigned = rsa.unblind(messageBlinded, publicKeys.pub_n);
console.log('Message Unblinded Signed   : ' + messageUnblindedSigned);

const messageUnblindedVerified = rsa.blindVerify(messageUnblindedSigned, publicKeys.pub_e, publicKeys.pub_n);
//const messageUnblindedVerified = rsa.blindVerify(messageBlindedSigned, publicKeys.pub_e, publicKeys.pub_n);
console.log('Message Unblided Verified  : ' + messageUnblindedVerified);

