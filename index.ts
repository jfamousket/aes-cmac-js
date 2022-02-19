/**
 * Test Vectors
 */
import { encrypt } from './aes-cmac';
import sjcl = require('sjcl');
// @ts-ignore
console.log(sjcl.beware["CBC mode is dangerous because it doesn't protect message integrity."]()
)
console.log(sjcl)
/**
 * Subkey Generation
 * K                2b7e1516 28aed2a6 abf71588 09cf4f3c
 * AES-128(key,0)   7df76b0c 1ab899b3 3e42f047 b91b546f
 * K1               fbeed618 35713366 7c85e08f 7236a8de
 * K2               f7ddac30 6ae266cc f90bc11e e46d513b
 */
const cmac = encrypt(
  '0x2b7e151628aed2a6abf7158809cf4f3c',
  '0x00000000000000000000000000000000'
);
// Test AES-128 on zero initialization vector
const aes_0 = sjcl.codec.hex.toBits('0x7df76b0c1ab899b33e42f047b91b546f');
sjcl.bitArray.equal(cmac, aes_0)
  ? console.log('AES test passed!')
  : console.error('AES test failed!');
