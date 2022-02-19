/**
 * Test Vectors
 */
import { AesCmac } from "./aes-cmac";
import sjcl = require("./sjcl");

/**
 * Subkey Generation
 * K                2b7e1516 28aed2a6 abf71588 09cf4f3c
 * AES-128(key,0)   7df76b0c 1ab899b3 3e42f047 b91b546f
 * K1               fbeed618 35713366 7c85e08f 7236a8de
 * K2               f7ddac30 6ae266cc f90bc11e e46d513b
 */

// Test AES-128 on zero initialization vector
const cmac = new AesCmac("0x2b7e151628aed2a6abf7158809cf4f3c");
const t_0 = cmac.encrypt(
  sjcl.codec.hex.toBits("0x00000000000000000000000000000000")
);
const aes_0 = sjcl.codec.hex.toBits("0x7df76b0c1ab899b33e42f047b91b546f");
sjcl.bitArray.equal(t_0, aes_0)
  ? console.log("AES test passed!")
  : console.error("AES test failed!");

// Test subkey equality
const subkeys = cmac.generateSubkeys();
const K1 = sjcl.codec.hex.toBits("0xfbeed618357133667c85e08f7236a8de");
sjcl.bitArray.equal(subkeys["K1"], K1)
  ? console.log("K1 test passed!")
  : console.error("K1 test failed!");
const K2 = sjcl.codec.hex.toBits("0xf7ddac306ae266ccf90bc11ee46d513b");
sjcl.bitArray.equal(subkeys["K2"], K2)
  ? console.log("K2 test passed!")
  : console.error("K2 test failed!");

/**
 * <pre>
 * Example 1: len = 0
 * M              &lt;empty string&gt;
 * AES-CMAC       bb1d6929 e9593728 7fa37d12 9b756746
 * </pre>
 */
const m1 = "";
const cmac1 = cmac.generateCmac(m1);
const ex1 = sjcl.codec.hex.toBits("0xbb1d6929e95937287fa37d129b756746");
sjcl.bitArray.equal(ex1, cmac1)
  ? console.log("cmac1 test passed!")
  : console.error("cmac1 test failed!");
if (sjcl.codec.hex.fromBits(cmac1) !== "bb1d6929e95937287fa37d129b756746")
  console.error(
    sjcl.codec.hex.fromBits(cmac1) + " !== bb1d6929e95937287fa37d129b756746"
  );

/**
 * <pre>
 * Example 2: len = 16
 * M              6bc1bee2 2e409f96 e93d7e11 7393172a
 * AES-CMAC       070a16b4 6b4d4144 f79bdd9d d04a287c
 * </pre>
 */
const m2 = "0x6bc1bee22e409f96e93d7e117393172a";
const cmac2 = cmac.generateCmac(m2);
const ex2 = sjcl.codec.hex.toBits("0x070a16b46b4d4144f79bdd9dd04a287c");
sjcl.bitArray.equal(ex2, cmac2)
  ? console.log("cmac2 test passed!")
  : console.error("cmac2 test failed!");

/**
 * <pre>
 * Example 3: len = 40
 * M              6bc1bee2 2e409f96 e93d7e11 7393172a
 *                ae2d8a57 1e03ac9c 9eb76fac 45af8e51
 *                30c81c46 a35ce411
 * AES-CMAC       dfa66747 de9ae630 30ca3261 1497c827
 * </pre>
 */
const m3 =
  "0x6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411";
const cmac3 = cmac.generateCmac(m3);
const ex3 = sjcl.codec.hex.toBits("0xdfa66747de9ae63030ca32611497c827");
sjcl.bitArray.equal(ex3, cmac3)
  ? console.log("cmac3 test passed!")
  : console.error("cmac3 test failed!");

/**
 * <pre>
 * Example 4: len = 64
 * M              6bc1bee2 2e409f96 e93d7e11 7393172a
 *                ae2d8a57 1e03ac9c 9eb76fac 45af8e51
 *                30c81c46 a35ce411 e5fbc119 1a0a52ef
 *                f69f2445 df4f9b17 ad2b417b e66c3710
 * AES-CMAC       51f0bebf 7e3b9d92 fc497417 79363cfe
 * </pre>
 */
const m4 =
  "0x6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51" +
  "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";
const cmac4 = cmac.generateCmac(m4);
const ex4 = sjcl.codec.hex.toBits("0x51f0bebf7e3b9d92fc49741779363cfe");
sjcl.bitArray.equal(ex4, cmac4)
  ? console.log("cmac4 test passed!")
  : console.error("cmac4 test failed!");
