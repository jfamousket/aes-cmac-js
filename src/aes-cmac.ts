import SJCL from './sjcl'

// @ts-expect-error
SJCL.beware[
  "CBC mode is dangerous because it doesn't protect message integrity."
]()

const Aes = SJCL.cipher.aes
export class AesCmac {
  static Bsize = 128 // in bits! not octets (16)
  static Zero = SJCL.codec.hex.toBits('0x00000000000000000000000000000000')
  static Rb = SJCL.codec.hex.toBits('0x00000000000000000000000000000087')
  private readonly cipher: SJCL.SjclCipher

  /**
   * @param key Key as Hex string
   */
  constructor (key: string) {
    const keyBits = SJCL.codec.hex.toBits(key)
    this.cipher = new Aes(keyBits)
  }

  /**
   *
   */
  xor4Words = (x: SJCL.BitArray, y: SJCL.BitArray): number[] => {
    return [x[0] ^ y[0], x[1] ^ y[1], x[2] ^ y[2], x[3] ^ y[3]]
  }

  /**
   *
   */
  simpleShiftLeft = (a: SJCL.BitArray, shift: number): SJCL.BitArray => {
    return SJCL.bitArray.bitSlice(
      SJCL.bitArray.concat(a, [0]),
      shift,
      AesCmac.Bsize + shift
    )
  }

  /**
   * @param message Message as `BitArray`
   */
  iso7816d4Padding = (message: SJCL.BitArray): SJCL.BitArray => {
    const bitLength = SJCL.bitArray.bitLength(message)
    message = this.xor4Words(message, AesCmac.Zero)
    const gap = AesCmac.Bsize - bitLength
    if (gap < 8) return message
    let startWord = Math.floor(bitLength / 32)
    let startByte = Math.ceil((bitLength % 32) / 8) // 0,1,2,3,4
    if (startByte === 4) {
      console.log('rolled over into next word')
      startWord++
      startByte = 0
      if (startWord === 4) {
        // this should have been caught above on gap check
        console.warn("this shouldn't ever happen")
        return message
      }
    }
    let last32 = message[startWord]
    // startByte: 0->2^31, 1->2^23, 2->2^15, 3->2^7
    const bitmask = Math.pow(2, (4 - startByte) * 8 - 1)
    last32 |= bitmask
    message[startWord] = last32
    return message
  }

  /**
   * @param message `BitArray` message as array of bits
   */
  encrypt = (message: SJCL.BitArray): SJCL.BitArray => {
    return SJCL.bitArray.clamp(
      SJCL.mode.cbc.encrypt(this.cipher, message, AesCmac.Zero),
      AesCmac.Bsize
    )
  }

  /**
   * @param plainText Text as Hex string
   */
  generateCmac = (plainText: string): SJCL.BitArray => {
    // Step 1
    const subkeys = this.generateSubkeys()

    // Step 2
    const M = SJCL.codec.hex.toBits(plainText)
    const len = SJCL.bitArray.bitLength(M) // in bits! not octets
    let n = Math.ceil(len / AesCmac.Bsize)

    // Step 3
    let lastBlockComplete: boolean
    if (n === 0) {
      n = 1
      lastBlockComplete = false
    } else {
      if (len % AesCmac.Bsize === 0) lastBlockComplete = true
      else lastBlockComplete = false
    }

    // Step 4
    const lastStart = (n - 1) * AesCmac.Bsize
    let last = SJCL.bitArray.bitSlice(M, lastStart)
    if (lastBlockComplete) {
      last = this.xor4Words(last, subkeys.K1)
    } else {
      last = this.iso7816d4Padding(last)
      last = this.xor4Words(last, subkeys.K2)
    }

    // Step 5
    let X = AesCmac.Zero
    let Y: SJCL.BitArray

    // Step 6
    for (let i = 1; i <= n - 1; i++) {
      const start = (i - 1) * AesCmac.Bsize
      const end = i * AesCmac.Bsize
      const mI = SJCL.bitArray.bitSlice(M, start, end)
      Y = this.xor4Words(X, mI)
      X = this.encrypt(Y)
    }
    Y = this.xor4Words(last, X)
    // Step 7
    return this.encrypt(Y)
  }

  generateSubkeys = (): { K1: SJCL.BitArray, K2: SJCL.BitArray } => {
    // Step 1
    const L = this.encrypt(AesCmac.Zero)

    // Step 2
    let msbNeg = L[0] & 0x80000000
    let K1 = this.simpleShiftLeft(L, 1)
    if (msbNeg !== 0) {
      K1 = this.xor4Words(K1, AesCmac.Rb)
    }

    // Step 3
    msbNeg = K1[0] & 0x80000000
    let K2 = this.simpleShiftLeft(K1, 1)
    if (msbNeg !== 0) {
      K2 = this.xor4Words(K2, AesCmac.Rb)
    }

    // Step 4
    return {
      K1: K1,
      K2: K2
    }
  }
}
