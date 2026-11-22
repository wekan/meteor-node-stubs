# elliptic 6.6.1, with the RFC 6979 nonce fix

A copy of [elliptic](https://github.com/indutny/elliptic) 6.6.1, the newest
release, for the `crypto` stub (`crypto-browserify`, through `browserify-sign`
and `create-ecdh`). `package.json` installs it with `"elliptic":
"file:vendor/elliptic"` and an `overrides` entry, so every package in the tree
uses this copy, and `bundledDependencies` ships it in the published package.

The one change is in `lib/elliptic/ec/index.js`, `EC.prototype.sign`: the
DRBG output for `k` is passed to `_truncateToN` as octets instead of as a BN,
so its length is the length generated. Elliptic 6.6.1 measured it without
leading zero octets, and on a curve whose order is not a whole number of
octets (P-521) a `k` that began with a zero octet was shifted by the wrong
amount - a `k` other than RFC 6979's, which together with a correct
signature of the same message reveals the private key
([GHSA-848j-6mx2-7j84](https://github.com/advisories/GHSA-848j-6mx2-7j84),
which lists every elliptic release as affected). `test/elliptic-rfc6979.js`
checks the signatures against an independent RFC 6979 and Node.js crypto.

## LICENSE

This software is licensed under the MIT License.

Copyright Fedor Indutny, 2014.

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to permit
persons to whom the Software is furnished to do so, subject to the
following conditions:

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
USE OR OTHER DEALINGS IN THE SOFTWARE.
