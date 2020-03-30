export class rsa {
    /** Constructor
     *
     * @param {number} bitLength
     */
    constructor(bitLength$1: any);
    bitLength: any;
    p: bigint;
    q: bigint;
    n: bigint;
    phi: bigint;
    e: bigint;
    d: any;
    stat: boolean;
    /** R random number generator.
     *
     * @param {string} n
     * @returns {{r_key: string, r_inv_key: string}}
     */
    getR(n: string): {
        r_key: string;
        r_inv_key: string;
    };
    r: bigint;
    r_inv: any;
    /** return e and n public keys for encrypt foreign person.
     *
     * @returns {*}
     */
    keys(): any;
    /** blind input message
     *
     * @param {string} m
     * @param {string} e
     * @param {string} n
     * @returns {string}
     */
    blind(m: string, e: string, n: string): string;
    /**
     *
     * @param {string} n
     * @param {string} m
     * @returns {string}
     */
    unblind(m: string, n: string): string;
    /** Encrypt message: m function with e and n public foreign keys.
     *
     * @param {string} m
     * @param {string} e
     * @param {string} n
     * @returns {null|string}
     */
    encrypt(m: string, e: string, n: string): string;
    /** verify signed hash function
      *
      * @param {string} s
      * @param {string} e
      * @param {string} n
      * @returns {null|string}
      */
    verify(s: string, e: string, n: string): string;
    /** verify a blind message
     *
     * @param {string} s
     * @param {string} e
     * @param {string} n
     * @returns {null|string}
     */
    blindVerify(s: string, e: string, n: string): string;
    /** decrypt message function
     *
     * @param {string} c
     * @returns {string|null}
     */
    decrypt(c: string): string;
    /** sign hash function
     *
     * @param {string} h
     * @returns {string|any}
     */
    sign(h: string): any;
    /** Sign a blinded message
     *
     * @param {string} h
     * @returns {null|string}
     */
    blindSign(h: string): string;
    /** verify that message is smaller than n
     *
     * @param {number} m
     * @returns {boolean}
     */
    valVerify(m: number): boolean;
    /** verify bitLength
     *
     * @param {number} bl
     * @returns {boolean}
     */
    bitLengthVerify(bl: number): boolean;
}
