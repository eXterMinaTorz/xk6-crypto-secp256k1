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
