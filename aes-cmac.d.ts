import sjcl = require("./sjcl");
export declare class AesCmac {
    static Bsize: number;
    static Zero: sjcl.BitArray;
    static Rb: sjcl.BitArray;
    private cipher;
    /**
     * @param key Key as Hex string
     */
    constructor(key: string);
    /**
     *
     */
    xor4Words: (x: sjcl.BitArray, y: sjcl.BitArray) => number[];
    /**
     *
     */
    simpleShiftLeft: (a: sjcl.BitArray, shift: number) => sjcl.BitArray;
    /**
     * @param message Message as `BitArray`
     */
    iso7816d4Padding: (message: sjcl.BitArray) => sjcl.BitArray;
    /**
     * @param message `BitArray` message as array of bits
     */
    encrypt: (message: sjcl.BitArray) => sjcl.BitArray;
    /**
     * @param plainText Text as Hex string
     */
    generateCmac: (plainText: string) => sjcl.BitArray;
    generateSubkeys: () => {
        K1: sjcl.BitArray;
        K2: sjcl.BitArray;
    };
}
