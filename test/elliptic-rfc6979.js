'use strict';

// vendor/elliptic: ECDSA signatures use RFC 6979's k on every curve, also
// when the DRBG output begins with a zero octet (GHSA-848j-6mx2-7j84).
// Run: node test/elliptic-rfc6979.js

const assert = require('assert');
const nodeCrypto = require('crypto');
const BN = require('bn.js');
const EC = require('elliptic').ec;

let passed = 0;
function test(name, fn) { fn(); passed += 1; console.log('  ok -', name); }

assert.ok(require.resolve('elliptic').includes(require('path').join('vendor', 'elliptic')),
  'the tree uses vendor/elliptic');

// RFC 6979 3.2, written from the RFC with Node.js HMAC: the first k it tries.
function rfc6979FirstK(curve, hashName, privBytes, digest) {
  const n = curve.n;
  const rlen = n.byteLength();
  const qlen = n.bitLength();
  const hlen = nodeCrypto.createHash(hashName).digest().length;
  const int2octets = x => Buffer.from(x.toArray('be', rlen));
  const bits2int = octets => {
    let x = new BN(octets);
    const extra = octets.length * 8 - qlen;
    if (extra > 0) x = x.ushrn(extra);
    return x;
  };
  const bits2octets = octets => int2octets(bits2int(octets).umod(n));
  const hmac = (key, ...data) => {
    const h = nodeCrypto.createHmac(hashName, key);
    for (const d of data) h.update(d);
    return h.digest();
  };
  const x = int2octets(new BN(privBytes));
  const h1 = bits2octets(digest);
  let V = Buffer.alloc(hlen, 1);
  let K = Buffer.alloc(hlen, 0);
  K = hmac(K, V, Buffer.from([0]), x, h1);
  V = hmac(K, V);
  K = hmac(K, V, Buffer.from([1]), x, h1);
  V = hmac(K, V);
  let T = Buffer.alloc(0);
  while (T.length < rlen) { V = hmac(K, V); T = Buffer.concat([T, V]); }
  T = T.subarray(0, rlen);
  return { k: bits2int(T), octets: T, leadingZero: T[0] === 0 };
}

// The k elliptic 6.6.1 used: the same octets measured as a BN.
function ellipticOldK(curve, octetsK) {
  const asBn = new BN(octetsK);
  const delta = asBn.byteLength() * 8 - curve.n.bitLength();
  return delta > 0 ? asBn.ushrn(delta) : asBn;
}

function nodeVerifies(namedCurve, hashName, pub, msg, sig, bytes) {
  const der = { kty: 'EC', crv: namedCurve,
    x: Buffer.from(pub.getX().toArray('be', bytes)).toString('base64url'),
    y: Buffer.from(pub.getY().toArray('be', bytes)).toString('base64url') };
  const key = nodeCrypto.createPublicKey({ key: der, format: 'jwk' });
  const p1363 = Buffer.concat([Buffer.from(sig.r.toArray('be', bytes)), Buffer.from(sig.s.toArray('be', bytes))]);
  return nodeCrypto.verify(hashName, msg, { key, dsaEncoding: 'ieee-p1363' }, p1363);
}

for (const [name, namedCurve, hashName] of [['p521', 'P-521', 'sha512'], ['p256', 'P-256', 'sha256'], ['secp256k1', 'secp256k1', 'sha256']]) {
  test(`${name}: every signature uses RFC 6979's k and verifies with Node.js crypto`, () => {
    const ec = new EC(name);
    const bytes = ec.n.byteLength();
    const { privateKey } = nodeCrypto.generateKeyPairSync('ec', { namedCurve });
    const d = Buffer.from(privateKey.export({ format: 'jwk' }).d, 'base64url');
    const key = ec.keyFromPrivate(d);
    let leadingZeros = 0;
    let differsFromOld = 0;
    for (let i = 0; i < 3000 && (leadingZeros < 3 || i < 300); i += 1) {
      const msg = Buffer.from(`message ${i}`);
      const digest = nodeCrypto.createHash(hashName).update(msg).digest();
      const ref = rfc6979FirstK(ec, hashName, d, digest);
      const sig = key.sign(digest);
      const withRefK = key.sign(digest, { k: () => Array.from(ref.octets) });
      assert.ok(ec.g.mul(ref.k).getX().umod(ec.n).eq(sig.r), `message ${i}: r comes from RFC 6979's k`);
      assert.ok(sig.r.eq(withRefK.r) && sig.s.eq(withRefK.s), `message ${i}: k is RFC 6979's`);
      if (i < 50 || ref.leadingZero) assert.ok(nodeVerifies(namedCurve, hashName, key.getPublic(), msg, sig, bytes), `message ${i}: Node.js verifies`);
      if (ref.leadingZero) {
        leadingZeros += 1;
        const old = ellipticOldK(ec, ref.octets);
        if (!old.eq(ref.k)) differsFromOld += 1;
      }
    }
    assert.ok(leadingZeros >= 3, `messages whose DRBG output begins with a zero octet were signed (${leadingZeros})`);
    if (name === 'p521') {
      // Negative: on P-521 those are exactly the signatures 6.6.1 got wrong.
      assert.ok(differsFromOld > 0, 'the old k differs where the octets begin with zero');
    }
  });
}

test('negative: the vendored sign passes octets, not a BN, to _truncateToN', () => {
  const src = require('fs').readFileSync(require.resolve('elliptic/lib/elliptic/ec/index.js'), 'utf8');
  assert.ok(!/new BN\(drbg\.generate\(this\.n\.byteLength\(\)\)\)/.test(src), 'no BN-wrapped DRBG output for k');
  assert.match(src, /this\._truncateToN\(drbg\.generate\(this\.n\.byteLength\(\)\), true\)/);
});

console.log(`\nelliptic-rfc6979: ${passed} tests passed`);
