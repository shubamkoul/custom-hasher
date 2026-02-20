# custom-hasher

> ⚠️ **For educational purposes only.** Do **not** use this module to protect real passwords in production. Use well-audited libraries such as [bcrypt](https://www.npmjs.com/package/bcrypt), [argon2](https://www.npmjs.com/package/argon2), or Node's built-in `crypto.scrypt`.

A **zero-dependency** Node.js module that demonstrates a custom password-hashing algorithm built from first principles using bitwise operations, `Uint32Array` word processing, and salt generation.

---

## Features

| Feature | Detail |
|---|---|
| **Bitwise transform** | XOR mixing, left/right bit-rotation, modular 32-bit addition |
| **String → words** | Manual UTF-8 encoding to `Uint32Array` (handles emoji & multi-byte chars) |
| **Salt generation** | Alphanumeric salt via `Math.random` |
| **256-bit digest** | 64-character lowercase hex output |
| **Zero dependencies** | Pure Node.js, no `npm install` required |
| **Input validation** | `TypeError` / `RangeError` on bad inputs |

---

## Installation

```bash
npm install custom-hasher
```

Or clone and use locally:

```bash
git clone https://github.com/shubamkoul/custom-hasher.git
cd custom-hasher
node example.js
```

---

## Quick Start

```js
const { generateSalt, hashPassword } = require('custom-hasher');

const salt     = generateSalt();          // e.g. "Xk3mQ9tRpLzA7vYn"
const hash     = hashPassword('hunter2', salt);

console.log('Salt:', salt);
console.log('Hash:', hash);
// Hash: 3f8a1c7e...  (64 hex chars)

// Verification — recompute and compare
const isMatch = hashPassword('hunter2', salt) === hash;
console.log('Match:', isMatch); // true
```

---

## API Reference

### `generateSalt([length])`

Generate a random alphanumeric salt string.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `length` | `number` | `16` | Number of characters |

**Returns:** `string`  
**Throws:** `RangeError` if `length < 1`

```js
const salt = generateSalt(24); // "aB3xYz9QmKrTpWvL1nCsUjDh"
```

---

### `hashPassword(password, salt)`

Hash a password with the given salt.

| Parameter | Type | Description |
|---|---|---|
| `password` | `string` | Plain-text password (non-empty) |
| `salt` | `string` | Salt string (non-empty) |

**Returns:** `string` — 64-character lowercase hex digest  
**Throws:** `TypeError` for non-string arguments, `RangeError` for empty strings

```js
const hash = hashPassword('my$ecretPw!', salt);
```

---

### `stringToUint32Array(str)`

Convert a UTF-8 string to a big-endian `Uint32Array`.  
Useful for inspecting how the module processes input at word level.

```js
const { stringToUint32Array } = require('custom-hasher');
const words = stringToUint32Array('ABCD');
// Uint32Array [ 0x41424344 ]
```

---

### `bitwiseTransform(word, index)`

Apply 12 rounds of XOR / rotate / add transformation to a 32-bit word.  
`index` is the word's position in the input array, making output position-sensitive.

```js
const { bitwiseTransform } = require('custom-hasher');
const out = bitwiseTransform(0xdeadbeef, 0);
```

---

### Low-level helpers

```js
const { rotateLeft, rotateRight, addMod32 } = require('custom-hasher');

rotateLeft(0x80000000, 1);  // 0x00000001
rotateRight(0x00000001, 1); // 0x80000000
addMod32(0xffffffff, 1);    // 0x00000000
```

---

## Algorithm Design

```
password + salt
       │
       ▼
 stringToUint32Array()      UTF-8 → Uint32Array (big-endian, zero-padded)
       │
       ▼
 bitwiseTransform()  ×N     Per-word: 12 rounds of XOR + rotL + addMod32 + XOR + rotR
       │
       ▼
 Fold into 8-word state     XOR and modular-add into 256-bit accumulator
       │
       ▼
 Finalise state             One more bitwiseTransform pass on each state word
       │
       ▼
 Hex encode                 64-character lowercase hex string
```

---

## Running Tests

```bash
node test.js
```

All 30+ assertions cover: rotation identity, overflow wrapping, UTF-8 encoding edge-cases, determinism, avalanche (different index → different output), salt collisions, and input validation.

---

## License

MIT
