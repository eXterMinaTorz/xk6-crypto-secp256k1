# xk6-crypto-secp256k1

A public `xk6` extension for secp256k1 cryptography in k6 JavaScript tests.  
Provides key generation, signing, verification, and ECDH using the secp256k1 curve.

## Installation

Build k6 with this extension:

```sh
xk6 build --with github.com/exterminatorz/xk6-crypto-secp256k1
```

## Usage Example (k6 script)

```js
import secp256k1 from 'k6/x/secp256k1';
import encoding from 'k6/encoding';
import { check } from 'k6';

export default function () {
  console.log('--- Key Generation ---');
  const keyPair1 = secp256k1.generateKey();
  const priv1 = keyPair1.privateKey;
  const pub1 = keyPair1.publicKey;

  console.log('Private key (b64):', encoding.b64encode(secp256k1.exportKey(priv1, 'raw')));
  console.log('Public key (b64):', encoding.b64encode(secp256k1.exportKey(pub1, 'raw')));

  console.log('\n--- Signing & Verification ---');
  const msg = stringToArrayBuffer('Hello k6 + secp256k1!');

  const sig = secp256k1.sign(priv1, msg);
  const valid = secp256k1.verify(pub1, msg, sig);

  check(null, { 'signature valid': () => valid });
  console.log('Signature (b64):', encoding.b64encode(sig));
  console.log('Signature valid?', valid);

  console.log('\n--- ECDH Shared Secret ---');
  const keyPair2 = secp256k1.generateKey();
  const priv2 = keyPair2.privateKey;
  const pub2 = keyPair2.publicKey;

  const shared1 = secp256k1.deriveBits(priv1, pub2);
  const shared2 = secp256k1.deriveBits(priv2, pub1);

  check(null, { 'shared secrets match': () => encoding.b64encode(shared1) === encoding.b64encode(shared2) });
  console.log('Shared Secret (b64):', encoding.b64encode(shared1));
  console.log('Shared secrets match?', encoding.b64encode(shared1) === encoding.b64encode(shared2));

  console.log('\n--- Public Key Import / Export ---');
  const exportedPub = secp256k1.exportKey(pub1, 'raw');
  const importedPub = secp256k1.importKey({ Name: 'ECDSA', NamedCurve: 'secp256k1' }, 'raw', exportedPub, ['verify']);

  const importedPubBytes = secp256k1.exportKey(importedPub, 'raw');
  console.log('Imported Public Key (b64):', encoding.b64encode(importedPubBytes));

  // Verify a signature with the imported key
  const validImported = secp256k1.verify(importedPub, msg, sig);
  check(null, { 'signature valid with imported pub': () => validImported });
  console.log('Signature valid with imported key?', validImported);
}

// Helper: convert string → ArrayBuffer for k6
function stringToArrayBuffer(str) {
  const buf = new ArrayBuffer(str.length * 2); // 2 bytes per char
  const view = new Uint16Array(buf);
  for (let i = 0; i < str.length; i++) {
    view[i] = str.charCodeAt(i);
  }
  return buf;
}
```

## Supported Crypto Methods

| Function                                  | Input                                    | Output                                          | Description                                   |
| ----------------------------------------- | ---------------------------------------- | ----------------------------------------------- | --------------------------------------------- |
| `generateKey()`                           | —                                        | `[privateKey: CryptoKey, publicKey: CryptoKey]` | Generates a secp256k1 key pair.               |
| `importPublicKey(pubB64)`                 | Base64 public key                        | `CryptoKey`                                     | Import a public key from Base64.              |
| `sign(privKey, data)`                     | `CryptoKey` + `ArrayBuffer`              | DER-encoded signature (`ArrayBuffer`)           | Sign a message using a private key.           |
| `verify(pubKey, data, sig)`               | `CryptoKey`, `ArrayBuffer`, signature    | `boolean`                                       | Verify a message signature with a public key. |
| `deriveBits(privKey, pubKey)`             | `CryptoKey`, `CryptoKey`                 | Shared secret bytes (`ArrayBuffer`)             | Compute ECDH shared secret.                   |
| `ImportKey(params, format, data, usages)` | Import params, format, key bytes, usages | `CryptoKey`                                     | Flexible import for raw/SPKI/PKCS8/JWK.       |

> All keys are returned as **CryptoKey objects**, exposing:
>
> - `PrivateKey` (Uint8Array/ArrayBuffer) — present for private keys
> - `PublicKey` (Uint8Array/ArrayBuffer) — present for public keys
> - `Algorithm` — `"secp256k1"`
> - `Extractable` — always `true`
> - `Type` — `"private"` | `"public"`

## Notes

- No `TextEncoder` exists in k6; use the included helper function `stringToArrayBuffer`.
- Currently, only key generation, signing, verification, and ECDH are supported.  
  ECIES, full private key import/export, and digest are **not implemented**.

## Running the example

```sh
# Build k6 with this extension
xk6 build --with github.com/exterminatorz/xk6-crypto-secp256k1

# Run the example script
k6 run examples/k6_example.js
```

## License

MIT
