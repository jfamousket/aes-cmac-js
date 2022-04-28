import SJCL from './sjcl';
export declare class AesCmac {
    static Bsize: number;
    static Zero: SJCL.BitArray;
    static Rb: SJCL.BitArray;
    private readonly cipher;
    /**
     * @param key Key as Hex string
     */
    constructor(key: string);
    /**
     *
     */
    xor4Words: (x: SJCL.BitArray, y: SJCL.BitArray) => number[];
    /**
     *
     */
    simpleShiftLeft: (a: SJCL.BitArray, shift: number) => SJCL.BitArray;
    /**
     * @param message Message as `BitArray`
     */
    iso7816d4Padding: (message: SJCL.BitArray) => SJCL.BitArray;
    /**
     * @param message `BitArray` message as array of bits
     */
    encrypt: (message: SJCL.BitArray) => SJCL.BitArray;
    /**
     * @param plainText Text as Hex string
     */
    generateCmac: (plainText: string) => SJCL.BitArray;
    generateSubkeys: () => {
        K1: SJCL.BitArray;
        K2: SJCL.BitArray;
    };
}
