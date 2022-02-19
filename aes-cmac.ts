import sjcl = require('sjcl');

const Bsize = 128; // in bits! not octets (16)
const Zero = sjcl.codec.hex.toBits('0x00000000000000000000000000000000');
const Rb = sjcl.codec.hex.toBits('0x00000000000000000000000000000087');

/**
 * @param key Key as Hex string
 */
const generateKey = (key: string) => {
  const keyBits = sjcl.codec.hex.toBits(key);
  return new sjcl.cipher.aes(keyBits);
};

/**
 *
 */
const xor4Words = (x: sjcl.BitArray, y: sjcl.BitArray) => {
  return [x[0] ^ y[0], x[1] ^ y[1], x[2] ^ y[2], x[3] ^ y[3]];
};

/**
 *
 */
const simpleShiftLeft = (a: sjcl.BitArray, shift: number) => {
  return sjcl.bitArray.bitSlice(
    sjcl.bitArray.concat(a, [0]),
    shift,
    Bsize + shift
  );
};

/**
 * @param message Message as `BitArray`
 */
const iso7816d4Padding = (message: sjcl.BitArray) => {
  const bitLength = sjcl.bitArray.bitLength(message);
  message = xor4Words(message, Zero);
  const gap = Bsize - bitLength;
  if (gap < 8) return message;
  let startWord = Math.floor(bitLength / 32);
  let startByte = Math.ceil((bitLength % 32) / 8); // 0,1,2,3,4
  if (startByte == 4) {
    console.log('rolled over into next word');
    startWord++;
    startByte = 0;
    if (startWord == 4) {
      // this should have been caught above on gap check
      console.warn("this shouldn't ever happen");
      return message;
    }
  }
  let last32 = message[startWord];
  // startByte: 0->2^31, 1->2^23, 2->2^15, 3->2^7
  const bitmask = Math.pow(2, (4 - startByte) * 8 - 1);
  last32 |= bitmask;
  message[startWord] = last32;
  return message;
};

/**
 * @param message `BitArray` message as array of bits
 * @param key Key as Hex string
 */
const _encrypt = (message: sjcl.BitArray, key: string) => {
  return sjcl.bitArray.clamp(
    sjcl.mode.cbc.encrypt(generateKey(key), message, Zero),
    Bsize
  );
};

/**
 * @param key Key as Hex string
 * @param plainText Text as Hex string
 */
export const encrypt = (key: string, plainText: string) => {
  // Step 1
  const subkeys = generateSubkeys(key);

  // Step 2
  const M = sjcl.codec.hex.toBits(plainText);
  const len = sjcl.bitArray.bitLength(M); // in bits! not octets
  let n = Math.ceil(len / Bsize);

  // Step 3
  let lastBlockComplete;
  if (n == 0) {
    n = 1;
    lastBlockComplete = false;
  } else {
    if (len % Bsize == 0) lastBlockComplete = true;
    else lastBlockComplete = false;
  }

  // Step 4
  const lastStart = (n - 1) * Bsize;
  let M_last = sjcl.bitArray.bitSlice(M, lastStart, 0);
  if (lastBlockComplete) {
    M_last = xor4Words(M_last, subkeys['K1']);
  } else {
    M_last = iso7816d4Padding(M_last);
    M_last = xor4Words(M_last, subkeys['K2']);
  }

  // Step 5
  let X = Zero;
  let Y;

  // Step 6
  for (let i = 1; i <= n - 1; i++) {
    const start = (i - 1) * Bsize;
    const end = i * Bsize;
    const M_i = sjcl.bitArray.bitSlice(M, start, end);
    Y = xor4Words(X, M_i);
    X = _encrypt(Y, key);
  }
  Y == xor4Words(M_last, X);
  // Step 7
  return _encrypt(Y, key);
};

/**
 * @param key Key as Hex string
 */
const generateSubkeys = (key: string) => {
  // Step 1
  const L = _encrypt(Zero, key);

  // Step 2
  let msbNeg = L[0] & 0x80000000;
  const K1 = simpleShiftLeft(L, 1);
  if (msbNeg) {
    K1 == xor4Words(K1, Rb);
  }

  // Step 3
  msbNeg = K1[0] & 0x80000000;
  let K2 = simpleShiftLeft(K1, 1);
  if (msbNeg) {
    K2 = xor4Words(K2, Rb);
  }

  // Step 4
  return {
    K1: K1,
    K2: K2,
  };
};
