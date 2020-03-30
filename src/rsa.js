'use strict';

import * as bcu from 'bigint-crypto-utils';
import * as bc from 'bigint-conversion';

const _ONE = BigInt(1);

export class rsa {
    /** Constructor
     *
     * @param {number} bitLength
     */
    constructor(bitLength) {
        this.bitLength = bitLength;
        do {
            this.p = bcu.primeSync(Math.round(bitLength / 2) + 1);
            this.q = bcu.primeSync(Math.round(bitLength / 2));
            this.n = this.p * this.q;
        } while (this.p === this.q || bcu.bitLength(this.n) != bitLength);

        this.phi = (this.p - _ONE) * (this.q - _ONE);
        this.e = BigInt(65537);
        this.d = bcu.modInv(this.e, this.phi);
        this.stat = true;
    }

    /** R random number generator.
     *
     * @param {string} n
     * @returns {{r_key: string, r_inv_key: string}}
     */
    getR(n){
        n = bc.hexToBigint(n);
        let counter = 0;
        do{
            counter ++;
            this.r = bcu.primeSync(this.bitLength);
        }while (this.r >= n || bcu.gcd(this.r, n) != _ONE);

        this.r_inv = bcu.modInv(this.r, n);

        return {r_key: bc.bigintToHex(this.r), r_inv_key: bc.bigintToHex(this.r_inv), attempts: counter};
    }

    /** return e and n public keys for encrypt foreign person.
     *
     * @returns {*}
     */
    keys(){
        return {pub_e: bc.bigintToHex(this.e), pub_n: bc.bigintToHex(this.n)};
    }

    /** blind input message
     *
     * @param {string} m
     * @param {string} e
     * @param {string} n
     * @returns {string}
     */
    blind(m, e, n){
        m = bc.textToBigint(m);
        e = bc.hexToBigint(e);
        n = bc.hexToBigint(n);
        const r = bcu.modPow(this.r, e, n);
         return bc.bigintToHex((m * r) % n);
    }

    /**
     *
     * @param {string} n
     * @param {string} m
     * @returns {string}
     */
    unblind(m, n){
        m = bc.hexToBigint(m);
        n = bc.hexToBigint(n);
        return bc.bigintToHex((m * this.r_inv) % n);
    }

    /** Encrypt message: m function with e and n public foreign keys.
     *
     * @param {string} m
     * @param {string} e
     * @param {string} n
     * @returns {null|string}
     */
    encrypt(m, e, n) {
        m = bc.textToBigint(m);
        e = bc.hexToBigint(e);
        n = bc.hexToBigint(n);
        if (this.valVerify(m)) {
            console.log("Message to encrypt > n");
            return null;
        } else return bc.bigintToHex(bcu.modPow(m, e, n));
    }

   /** verify signed hash function
     *
     * @param {string} s
     * @param {string} e
     * @param {string} n
     * @returns {null|string}
     */
    verify(s, e, n) {
        s = bc.textToBigint(s);
        e = bc.hexToBigint(e);
        n = bc.hexToBigint(n);
        if (this.valVerify(s)) {
            console.log("Message to verify > n");
            return null;
        } else return bc.bigintToHex(bcu.modPow(s, e, n));
    }

    /** verify a blind message
     *
     * @param {string} s
     * @param {string} e
     * @param {string} n
     * @returns {null|string}
     */
    blindVerify(s, e, n){
        s = bc.hexToBigint(s);
        e = bc.hexToBigint(e);
        n = bc.hexToBigint(n);
        if (this.valVerify(s)) {
            console.log("Message to verify > n");
            return null;
        } else return bc.bigintToText(bcu.modPow(s, e, n));
    }

    /** decrypt message function
     *
     * @param {string} c
     * @returns {string|null}
     */
    decrypt(c) {
        c = bc.hexToBigint(c);
        if (this.valVerify(c)) {
            console.log("Message to decrypt > n");
            return null;
        } else return bc.bigintToText(bcu.modPow(c, this.d, this.n));
    }

    /** sign hash function
     *
     * @param {string} h
     * @returns {string|any}
     */
    sign(h) {
        h = bc.textToBigint(h);
        if (this.valVerify(h)) {
            console.log("Message to sign > n");
            return null;
        } else return bc.bigintToHex(bcu.modPow(h, this.d, this.n));
    }

    /** Sign a blinded message
     *
     * @param {string} h
     * @returns {null|string}
     */
    blindSign(h){
        h = bc.hexToBigint(h);
        if (this.valVerify(h)) {
            console.log("Message to sign > n");
            return null;
        } else return bc.bigintToHex(bcu.modPow(h, this.d, this.n));
    }

    /** verify that message is smaller than n
     *
     * @param {number} m
     * @returns {boolean}
     */
    valVerify(m) {
        if ((m > this.n))
            console.log("message is greater than n");
        return m > this.n;
    }

    /** verify bitLength
     *
     * @param {number} bl
     * @returns {boolean}
     */
    bitLengthVerify(bl) {
        if (bl % 8) return false;
        else return true;
    }
}
