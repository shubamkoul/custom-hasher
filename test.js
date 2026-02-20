'use strict';

/**
 * Minimal self-contained test suite for custom-hasher.
 * Run with: node test.js
 */

const {
    rotateLeft,
    rotateRight,
    addMod32,
    stringToUint32Array,
    bitwiseTransform,
    generateSalt,
    hashPassword,
} = require('./index');

// ---------------------------------------------------------------------------
// Tiny test harness
// ---------------------------------------------------------------------------

let passed = 0;
let failed = 0;

function test(name, fn) {
    try {
        fn();
        console.log(`  ✅  ${name}`);
        passed++;
    } catch (err) {
        console.error(`  ❌  ${name}`);
        console.error(`      ${err.message}`);
        failed++;
    }
}

function assert(condition, msg) {
    if (!condition) throw new Error(msg || 'Assertion failed');
}

function assertEqual(a, b, msg) {
    if (a !== b) throw new Error(msg || `Expected ${JSON.stringify(b)}, got ${JSON.stringify(a)}`);
}

// ---------------------------------------------------------------------------
// rotateLeft
// ---------------------------------------------------------------------------

console.log('\n🔹 rotateLeft');

test('rotateLeft(1, 1) === 2', () => {
    assertEqual(rotateLeft(1, 1), 2);
});

test('rotateLeft(0x80000000, 1) === 1  (wrap-around)', () => {
    assertEqual(rotateLeft(0x80000000, 1), 1);
});

test('rotateLeft(x, 0) === x  (identity)', () => {
    assertEqual(rotateLeft(0xdeadbeef, 0), 0xdeadbeef >>> 0);
});

test('rotateLeft(x, 32) === x  (full rotation)', () => {
    assertEqual(rotateLeft(0xabcd1234, 32), 0xabcd1234 >>> 0);
});

// ---------------------------------------------------------------------------
// rotateRight
// ---------------------------------------------------------------------------

console.log('\n🔹 rotateRight');

test('rotateRight(2, 1) === 1', () => {
    assertEqual(rotateRight(2, 1), 1);
});

test('rotateRight(1, 1) === 0x80000000  (wrap-around)', () => {
    assertEqual(rotateRight(1, 1), 0x80000000 >>> 0);
});

test('rotateLeft then rotateRight is identity', () => {
    const orig = 0xfeedface >>> 0;
    for (let n = 0; n <= 31; n++) {
        assertEqual(rotateRight(rotateLeft(orig, n), n), orig, `failed at n=${n}`);
    }
});

// ---------------------------------------------------------------------------
// addMod32
// ---------------------------------------------------------------------------

console.log('\n🔹 addMod32');

test('addMod32(1, 1) === 2', () => {
    assertEqual(addMod32(1, 1), 2);
});

test('addMod32 wraps on 32-bit overflow', () => {
    assertEqual(addMod32(0xffffffff, 1), 0);
});

test('addMod32(0, 0) === 0', () => {
    assertEqual(addMod32(0, 0), 0);
});

// ---------------------------------------------------------------------------
// stringToUint32Array
// ---------------------------------------------------------------------------

console.log('\n🔹 stringToUint32Array');

test('empty string → zero-length array', () => {
    assertEqual(stringToUint32Array('').length, 0);
});

test('"ABCD" → 1 word (4 bytes, big-endian)', () => {
    const arr = stringToUint32Array('ABCD');
    assertEqual(arr.length, 1);
    // A=0x41, B=0x42, C=0x43, D=0x44
    assertEqual(arr[0], 0x41424344);
});

test('length pads to next multiple of 4', () => {
    const arr = stringToUint32Array('Hi!'); // 3 bytes → padded to 4
    assertEqual(arr.length, 1);
});

test('returns a Uint32Array instance', () => {
    assert(stringToUint32Array('test') instanceof Uint32Array);
});

test('unicode multi-byte character encodes correctly', () => {
    // '€' is U+20AC → 3 UTF-8 bytes: 0xE2, 0x82, 0xAC, pad 0x00
    const arr = stringToUint32Array('€');
    assertEqual(arr.length, 1);
    assertEqual(arr[0], 0xe282ac00);
});

// ---------------------------------------------------------------------------
// bitwiseTransform
// ---------------------------------------------------------------------------

console.log('\n🔹 bitwiseTransform');

test('returns a number', () => {
    assert(typeof bitwiseTransform(0, 0) === 'number');
});

test('same word, same index → same output (deterministic)', () => {
    assertEqual(bitwiseTransform(0xdeadbeef, 3), bitwiseTransform(0xdeadbeef, 3));
});

test('same word, different index → different output (positional sensitivity)', () => {
    const a = bitwiseTransform(0x12345678, 0);
    const b = bitwiseTransform(0x12345678, 1);
    assert(a !== b, `Expected a !== b, got a=${a}, b=${b}`);
});

test('result is an unsigned 32-bit integer', () => {
    const result = bitwiseTransform(0xffffffff, 0);
    assert(result >= 0 && result <= 0xffffffff);
});

// ---------------------------------------------------------------------------
// generateSalt
// ---------------------------------------------------------------------------

console.log('\n🔹 generateSalt');

test('default length is 16', () => {
    assertEqual(generateSalt().length, 16);
});

test('custom length is respected', () => {
    assertEqual(generateSalt(32).length, 32);
});

test('only alphanumeric characters', () => {
    const salt = generateSalt(200);
    assert(/^[A-Za-z0-9]+$/.test(salt), 'Salt contained non-alphanumeric characters');
});

test('two calls produce different salts (probabilistic)', () => {
    // Probability of collision is astronomically small (62^(-16) per pair).
    assert(generateSalt() !== generateSalt(), 'Two salts were identical — extremely unlikely');
});

test('throws RangeError for length < 1', () => {
    let threw = false;
    try { generateSalt(0); } catch (e) { threw = e instanceof RangeError; }
    assert(threw, 'Expected RangeError for length=0');
});

// ---------------------------------------------------------------------------
// hashPassword
// ---------------------------------------------------------------------------

console.log('\n🔹 hashPassword');

test('returns a 64-character hex string', () => {
    const hash = hashPassword('secret', 'mysalt');
    assertEqual(hash.length, 64);
    assert(/^[0-9a-f]{64}$/.test(hash), `Not a valid hex string: ${hash}`);
});

test('same inputs → same hash (deterministic)', () => {
    assertEqual(hashPassword('password', 'salt1'), hashPassword('password', 'salt1'));
});

test('different passwords → different hashes', () => {
    const h1 = hashPassword('password1', 'salt');
    const h2 = hashPassword('password2', 'salt');
    assert(h1 !== h2, 'Different passwords produced the same hash');
});

test('different salts → different hashes', () => {
    const h1 = hashPassword('password', 'saltA');
    const h2 = hashPassword('password', 'saltB');
    assert(h1 !== h2, 'Different salts produced the same hash');
});

test('long password is handled', () => {
    const long = 'a'.repeat(10000);
    const hash = hashPassword(long, 'salt');
    assertEqual(hash.length, 64);
});

test('unicode password is handled', () => {
    const hash = hashPassword('pässwörд💡', 'unicodeSalt');
    assertEqual(hash.length, 64);
});

test('throws TypeError for non-string password', () => {
    let threw = false;
    try { hashPassword(12345, 'salt'); } catch (e) { threw = e instanceof TypeError; }
    assert(threw, 'Expected TypeError for numeric password');
});

test('throws TypeError for non-string salt', () => {
    let threw = false;
    try { hashPassword('pw', null); } catch (e) { threw = e instanceof TypeError; }
    assert(threw, 'Expected TypeError for null salt');
});

test('throws RangeError for empty password', () => {
    let threw = false;
    try { hashPassword('', 'salt'); } catch (e) { threw = e instanceof RangeError; }
    assert(threw, 'Expected RangeError for empty password');
});

test('throws RangeError for empty salt', () => {
    let threw = false;
    try { hashPassword('pw', ''); } catch (e) { threw = e instanceof RangeError; }
    assert(threw, 'Expected RangeError for empty salt');
});

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

console.log(`\n${'─'.repeat(45)}`);
console.log(`Results: ${passed} passed, ${failed} failed out of ${passed + failed} tests.`);

if (failed > 0) {
    process.exit(1);
} else {
    console.log('All tests passed! 🎉\n');
}
