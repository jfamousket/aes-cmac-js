# AES-CMAC-JS

AES-CMAC implementation in pure javascript using [sjcl](https://github.com/bitwiseshiftleft/sjcl). See [RFC Spec](https://datatracker.ietf.org/doc/html/rfc4493#section-4).

For validation, this library contains passing test vectors taken from the `RFC spec`, see `tests/test.ts`.

# Example

```js
// pass your key here
const cmac = new AesCmac("0x2b7e151628aed2a6abf7158809cf4f3c");

// encrypt 0x000... using your key
const encrypted = cmac.encrypt(
  sjcl.codec.hex.toBits("0x00000000000000000000000000000000")
);
// expected output
const expected = sjcl.codec.hex.toBits("0x7df76b0c1ab899b33e42f047b91b546f");

// should be true
console.log(sjcl.bitArray.equal(t_0, aes_0));
```

# Testing

You can easily fork and try out a live version of the code [StackBlitz ⚡️](https://stackblitz.com/edit/typescript-uq8gt2)
