# custom-hasher

A **zero-dependency** Node.js module that demonstrates a custom password-hashing algorithm built from first principles using bitwise operations, `Uint32Array` word processing, and salt generation.

> ⚠️ **WARNING: For Educational Purposes Only!** ⚠️
> This module was built to demonstrate how hashing algorithms work under the hood. It uses `Math.random()` for salts and a custom algorithm that has **not** been cryptographically audited. Do **NOT** use this to store real passwords in production. Use established libraries like `bcrypt`, `argon2`, or `scrypt` instead.

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

### Recommended: Combined API

```js
const { hash, verify } = require('custom-hasher');

// 1. Hash a password (automatically generates a salt)
const storedHash = hash('hunter2');
console.log(storedHash);
// Output: $custom$v1$Xk3mQ9tRpLzA7vYn$3f8a1c7e...

// 2. Verify the password later
const isMatch = verify('hunter2', storedHash);
console.log('Match:', isMatch); // true
```

### Core Building Blocks

```js
const { generateSalt, hashPassword } = require('custom-hasher');

const salt     = generateSalt();          // e.g. "Xk3mQ9tRpLzA7vYn"
const rawHash  = hashPassword('hunter2', salt);

console.log('Salt:', salt);
console.log('Hash:', rawHash);
// Hash: 3f8a1c7e...  (64 hex chars)

// Verification — recompute and compare
const isMatch = hashPassword('hunter2', salt) === rawHash;
console.log('Match:', isMatch); // true
```

---

## API Reference

### `hash(password, [saltLength])`

Generate a salt and hash a password, returning a single combined string.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `password` | `string` | | Plain-text password to hash |
| `saltLength` | `number` | `16` | Optional length for the generated salt |

**Returns:** `string` — Format: `$custom$v1$<salt>$<hash>`

```js
const { hash } = require('custom-hasher');
const storedHash = hash('my$ecretPw!');
```

---

### `verify(password, storedHash)`

Verify a plain-text password against a combined hash string.

| Parameter | Type | Description |
|---|---|---|
| `password` | `string` | Plain-text password to verify |
| `storedHash` | `string` | The combined hash string output from `hash()` |

**Returns:** `boolean` — `true` if it matches, `false` otherwise (or if the format is invalid)

```js
const { verify } = require('custom-hasher');
const isValid = verify('my$ecretPw!', storedHash); // true
```

---

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
