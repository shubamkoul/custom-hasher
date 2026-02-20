/**
 * custom-hasher — A zero-dependency educational password hashing module.
 *
 * ⚠️  WARNING: This module is for EDUCATIONAL PURPOSES ONLY.
 *     Do NOT use this in production to store real passwords.
 *     For production use, rely on well-audited libraries such as bcrypt,
 *     argon2, or scrypt.
 *
 * Algorithm overview:
 *   1. Convert the UTF-8 password + salt string into a Uint32Array.
 *   2. Run each 32-bit word through a bitwise transformation pipeline
 *      (XOR mixing, left/right bit-rotation, modular addition).
 *   3. Merge all transformed words with a finalisation fold.
 *   4. Encode the result as a fixed-length hex string.
 */

'use strict';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Number of mixing rounds applied per 32-bit word. */
const ROUNDS = 12;

/** Magic seed used for the initial XOR state — chosen arbitrarily. */
const MAGIC_SEED = 0x9e3779b9; // ≈ 2³² / φ (golden-ratio constant)

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

/**
 * Rotate a 32-bit unsigned integer LEFT by `n` bits.
 *
 * JavaScript's `<<` operator works on signed 32-bit integers, so we must
 * use `>>> 0` to coerce back to an unsigned value after each operation.
 *
 * @param {number} value - 32-bit integer to rotate.
 * @param {number} n     - Number of bits to rotate (0–31).
 * @returns {number} Rotated 32-bit unsigned integer.
 */
function rotateLeft(value, n) {
  n = n & 31; // keep rotation in range [0, 31]
  return ((value << n) | (value >>> (32 - n))) >>> 0;
}

/**
 * Rotate a 32-bit unsigned integer RIGHT by `n` bits.
 *
 * @param {number} value - 32-bit integer to rotate.
 * @param {number} n     - Number of bits to rotate (0–31).
 * @returns {number} Rotated 32-bit unsigned integer.
 */
function rotateRight(value, n) {
  n = n & 31;
  return ((value >>> n) | (value << (32 - n))) >>> 0;
}

/**
 * Add two 32-bit integers with modular (overflow-safe) arithmetic.
 *
 * @param {number} a
 * @param {number} b
 * @returns {number} (a + b) mod 2³²
 */
function addMod32(a, b) {
  return (((a >>> 0) + (b >>> 0)) & 0xffffffff) >>> 0;
}

// ---------------------------------------------------------------------------
// Core building blocks
// ---------------------------------------------------------------------------

/**
 * Convert a plain string into a Uint32Array for word-level processing.
 *
 * The string is first encoded as UTF-8 bytes.  Groups of four consecutive
 * bytes are packed into a single big-endian 32-bit word.  If the byte count
 * is not a multiple of four, the final partial word is zero-padded.
 *
 * @param {string} str - Input string (UTF-8).
 * @returns {Uint32Array} Array of 32-bit words derived from the string.
 */
function stringToUint32Array(str) {
  // Encode each character to its UTF-8 byte sequence manually, so we remain
  // dependency-free and work in all Node.js versions ≥ 14.
  const bytes = [];

  for (let i = 0; i < str.length; i++) {
    const codePoint = str.codePointAt(i);

    if (codePoint === undefined) continue;

    // Advance index past surrogate pair if required.
    if (codePoint > 0xffff) i++;

    if (codePoint <= 0x7f) {
      bytes.push(codePoint);
    } else if (codePoint <= 0x7ff) {
      bytes.push(0xc0 | (codePoint >> 6));
      bytes.push(0x80 | (codePoint & 0x3f));
    } else if (codePoint <= 0xffff) {
      bytes.push(0xe0 | (codePoint >> 12));
      bytes.push(0x80 | ((codePoint >> 6) & 0x3f));
      bytes.push(0x80 | (codePoint & 0x3f));
    } else {
      bytes.push(0xf0 | (codePoint >> 18));
      bytes.push(0x80 | ((codePoint >> 12) & 0x3f));
      bytes.push(0x80 | ((codePoint >> 6) & 0x3f));
      bytes.push(0x80 | (codePoint & 0x3f));
    }
  }

  // Pad to the next multiple of 4.
  while (bytes.length % 4 !== 0) bytes.push(0);

  const words = new Uint32Array(bytes.length / 4);
  for (let i = 0; i < words.length; i++) {
    // Pack four bytes into one big-endian 32-bit word.
    words[i] =
      ((bytes[i * 4] << 24) |
        (bytes[i * 4 + 1] << 16) |
        (bytes[i * 4 + 2] << 8) |
        bytes[i * 4 + 3]) >>>
      0;
  }

  return words;
}

/**
 * Apply a multi-step bitwise transformation to a single 32-bit word.
 *
 * Each round performs:
 *   1. XOR  — Mix the word with a round-dependent key derived from the
 *              magic seed and the word index.
 *   2. Rotate left  — Avalanche effect: single bit changes propagate widely.
 *   3. Modular add  — Introduce non-linearity that XOR alone cannot provide.
 *   4. XOR again    — Additional diffusion with a complementary key.
 *   5. Rotate right — Counterbalance the left rotation; breaks symmetry.
 *
 * @param {number} word  - 32-bit unsigned integer to transform.
 * @param {number} index - Position of this word in the input array (used to
 *                         vary the round keys so identical words hash
 *                         differently depending on their position).
 * @returns {number} Transformed 32-bit unsigned integer.
 */
function bitwiseTransform(word, index) {
  let w = word >>> 0;

  for (let round = 0; round < ROUNDS; round++) {
    // Derive a pair of per-round keys from the magic seed, word index, and
    // round number.  Using both addition and XOR here prevents the keys
    // from colliding when index or round is zero.
    const keyA = addMod32(MAGIC_SEED, (index * 0x517cc1b7 + round * 0x6ed9eba1) >>> 0);
    const keyB = addMod32(MAGIC_SEED ^ 0xdeadbeef, (round * 0x8f1bbcdc + index * 0xa4d1c2ef) >>> 0);

    // Step 1 — XOR with keyA
    w = (w ^ keyA) >>> 0;

    // Step 2 — Left-rotation by a round-dependent amount (1–16 bits).
    const leftShift = (round % 16) + 1;
    w = rotateLeft(w, leftShift);

    // Step 3 — Modular addition (introduces arithmetic non-linearity).
    w = addMod32(w, keyB);

    // Step 4 — XOR with complemented keyA for additional diffusion.
    w = (w ^ (~keyA >>> 0)) >>> 0;

    // Step 5 — Right-rotation by a complementary amount to break symmetry.
    const rightShift = 32 - leftShift;
    w = rotateRight(w, rightShift);
  }

  return w;
}

/**
 * Generate a simple alphanumeric salt string.
 *
 * ⚠️  Uses Math.random(), which is NOT cryptographically secure.
 *     This is intentional for educational clarity.  In production, use
 *     `crypto.randomBytes()` (Node built-in, no extra dependency needed).
 *
 * @param {number} [length=16] - Desired salt length in characters.
 * @returns {string} Random alphanumeric salt.
 */
function generateSalt(length) {
  if (length === undefined) length = 16;
  if (typeof length !== 'number' || length < 1) {
    throw new RangeError('Salt length must be a positive number.');
  }

  const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let salt = '';

  for (let i = 0; i < length; i++) {
    salt += charset.charAt(Math.floor(Math.random() * charset.length));
  }

  return salt;
}

// ---------------------------------------------------------------------------
// Top-level hash function
// ---------------------------------------------------------------------------

/**
 * Hash a password with the given salt and return a hex-encoded digest.
 *
 * Steps:
 *   1. Concatenate salt + password (salt-first prevents length extension).
 *   2. Convert the combined string to a Uint32Array.
 *   3. Transform every word with `bitwiseTransform`.
 *   4. Fold all transformed words into a fixed 8-word (256-bit) state array
 *      using XOR and modular addition, with position-dependent mixing.
 *   5. Encode the 8-word state as a 64-character lowercase hex string.
 *
 * @param {string} password  - The plain-text password to hash.
 * @param {string} salt      - The salt to mix into the hash.
 * @returns {string} 64-character lowercase hex digest.
 *
 * @throws {TypeError}  If password or salt is not a string.
 * @throws {RangeError} If password or salt is an empty string.
 */
function hashPassword(password, salt) {
  if (typeof password !== 'string') throw new TypeError('password must be a string.');
  if (typeof salt !== 'string') throw new TypeError('salt must be a string.');
  if (password.length === 0) throw new RangeError('password must not be empty.');
  if (salt.length === 0) throw new RangeError('salt must not be empty.');

  // Salt prepended → same password with different salts yields different words
  // at every position, not just at a predictable suffix boundary.
  const combined = salt + '\x00' + password; // null byte separator

  const words = stringToUint32Array(combined);

  // Transform each word.
  const transformed = new Uint32Array(words.length);
  for (let i = 0; i < words.length; i++) {
    transformed[i] = bitwiseTransform(words[i], i);
  }

  // Fold into a fixed-size 8-word (256-bit) state.
  // The fold position varies per word to avoid XOR cancellation when the
  // same word value appears at two different indices.
  const STATE_SIZE = 8;
  const state = new Uint32Array(STATE_SIZE);

  // Initialise state with the magic seed so an all-zero input is non-trivial.
  for (let s = 0; s < STATE_SIZE; s++) {
    state[s] = addMod32(MAGIC_SEED, s * 0x27d4eb2f);
  }

  for (let i = 0; i < transformed.length; i++) {
    const slot = i % STATE_SIZE;
    const neighbor = (slot + 1) % STATE_SIZE;

    // Mix current word into the target slot via XOR.
    state[slot] = (state[slot] ^ transformed[i]) >>> 0;

    // Spread influence to the neighbouring slot via modular addition.
    state[neighbor] = addMod32(state[neighbor], rotateLeft(transformed[i], (i % 31) + 1));
  }

  // Finalisation: one more pass through the state to avalanche any
  // remaining structural patterns.
  for (let s = 0; s < STATE_SIZE; s++) {
    state[s] = bitwiseTransform(state[s], s + transformed.length);
  }

  // Encode as 64-character hex string.
  return Array.from(state)
    .map((w) => (w >>> 0).toString(16).padStart(8, '0'))
    .join('');
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

module.exports = {
  // Low-level utilities
  rotateLeft,
  rotateRight,
  addMod32,

  // Core building blocks
  stringToUint32Array,
  bitwiseTransform,

  // High-level API
  generateSalt,
  hashPassword,
};
