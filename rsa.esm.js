import { bitLength, primeSync, modInv, gcd, modPow } from 'bigint-crypto-utils';
import { hexToBigint, bigintToHex, textToBigint, bigintToText } from 'bigint-conversion';

const _ONE = BigInt(1);

class rsa {
    /** Constructor
     *
     * @param {number} bitLength
     */
    constructor(bitLength$1) {
        this.bitLength = bitLength$1;
        do {
            this.p = primeSync(Math.round(bitLength$1 / 2) + 1);
            this.q = primeSync(Math.round(bitLength$1 / 2));
            this.n = this.p * this.q;
        } while (this.p === this.q || bitLength(this.n) != bitLength$1);

        this.phi = (this.p - _ONE) * (this.q - _ONE);
        this.e = BigInt(65537);
        this.d = modInv(this.e, this.phi);
        this.stat = true;
    }

    /** R random number generator.
     *
     * @param {string} n
     * @returns {{r_key: string, r_inv_key: string}}
     */
    getR(n){
        n = hexToBigint(n);
        let counter = 0;
        do{
            counter ++;
            this.r = primeSync(this.bitLength);
        }while (this.r >= n || gcd(this.r, n) != _ONE);

        this.r_inv = modInv(this.r, n);

        return {r_key: bigintToHex(this.r), r_inv_key: bigintToHex(this.r_inv), attempts: counter};
    }

    /** return e and n public keys for encrypt foreign person.
     *
     * @returns {*}
     */
    keys(){
        return {pub_e: bigintToHex(this.e), pub_n: bigintToHex(this.n)};
    }

    /** blind input message
     *
     * @param {string} m
     * @param {string} e
     * @param {string} n
     * @returns {string}
     */
    blind(m, e, n){
        m = textToBigint(m);
        e = hexToBigint(e);
        n = hexToBigint(n);
        const r = modPow(this.r, e, n);
         return bigintToHex((m * r) % n);
    }

    /**
     *
     * @param {string} n
     * @param {string} m
     * @returns {string}
     */
    unblind(m, n){
        m = hexToBigint(m);
        n = hexToBigint(n);
        return bigintToHex((m * this.r_inv) % n);
    }

    /** Encrypt message: m function with e and n public foreign keys.
     *
     * @param {string} m
     * @param {string} e
     * @param {string} n
     * @returns {null|string}
     */
    encrypt(m, e, n) {
        m = textToBigint(m);
        e = hexToBigint(e);
        n = hexToBigint(n);
        if (this.valVerify(m)) {
            console.log("Message to encrypt > n");
            return null;
        } else return bigintToHex(modPow(m, e, n));
    }

   /** verify signed hash function
     *
     * @param {string} s
     * @param {string} e
     * @param {string} n
     * @returns {null|string}
     */
    verify(s, e, n) {
        s = textToBigint(s);
        e = hexToBigint(e);
        n = hexToBigint(n);
        if (this.valVerify(s)) {
            console.log("Message to verify > n");
            return null;
        } else return bigintToHex(modPow(s, e, n));
    }

    /** verify a blind message
     *
     * @param {string} s
     * @param {string} e
     * @param {string} n
     * @returns {null|string}
     */
    blindVerify(s, e, n){
        s = hexToBigint(s);
        e = hexToBigint(e);
        n = hexToBigint(n);
        if (this.valVerify(s)) {
            console.log("Message to verify > n");
            return null;
        } else return bigintToText(modPow(s, e, n));
    }

    /** decrypt message function
     *
     * @param {string} c
     * @returns {string|null}
     */
    decrypt(c) {
        c = hexToBigint(c);
        if (this.valVerify(c)) {
            console.log("Message to decrypt > n");
            return null;
        } else return bigintToText(modPow(c, this.d, this.n));
    }

    /** sign hash function
     *
     * @param {string} h
     * @returns {string|any}
     */
    sign(h) {
        h = textToBigint(h);
        if (this.valVerify(h)) {
            console.log("Message to sign > n");
            return null;
        } else return bigintToHex(modPow(h, this.d, this.n));
    }

    /** Sign a blinded message
     *
     * @param {string} h
     * @returns {null|string}
     */
    blindSign(h){
        h = hexToBigint(h);
        if (this.valVerify(h)) {
            console.log("Message to sign > n");
            return null;
        } else return bigintToHex(modPow(h, this.d, this.n));
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

export { rsa };
