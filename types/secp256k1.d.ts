// types/secp256k1.d.ts
declare module 'k6/x/secp256k1' {
  /**
   * Represents a cryptographic key (public or private) for secp256k1 operations.
   */
  export interface CryptoKey {
    /** Private key bytes, present only for private keys */
    privateKey?: ArrayBuffer | Uint8Array | null;
    /** Public key bytes, present for both private and public keys */
    publicKey?: ArrayBuffer | Uint8Array | null;
    /** Key algorithm information */
    algorithm: {
      name: string;
      namedCurve?: string;
    };
    /** Key type: 'private' or 'public' */
    type: 'private' | 'public';
    /** Whether the key material can be extracted */
    extractable: boolean;
    /** Allowed key usages (optional) */
    usages?: string[];
  }

  /**
   * Generate a new secp256k1 key pair.
   * @returns An object containing `privateKey` and `publicKey` of type CryptoKey
   */
  export function generateKey(): { privateKey: CryptoKey; publicKey: CryptoKey };

  /**
   * Sign a message using a private key.
   * @param priv Private key (CryptoKey)
   * @param msg Message to sign (ArrayBuffer, Uint8Array, or DataView)
   * @returns DER-encoded signature as ArrayBuffer
   */
  export function sign(priv: CryptoKey, msg: ArrayBuffer | ArrayBufferView | DataView): ArrayBuffer;

  /**
   * Verify a signature using a public key.
   * @param pub Public key (CryptoKey)
   * @param msg Original message (ArrayBuffer, Uint8Array, or DataView)
   * @param sig Signature to verify (ArrayBuffer or ArrayBufferView)
   * @returns `true` if signature is valid, `false` otherwise
   */
  export function verify(pub: CryptoKey, msg: ArrayBuffer | ArrayBufferView | DataView, sig: ArrayBuffer | ArrayBufferView): boolean;

  /**
   * Derive a shared secret using ECDH.
   * @param priv Private key (CryptoKey)
   * @param pub Peer public key (CryptoKey)
   * @returns Shared secret bytes as ArrayBuffer
   */
  export function deriveBits(priv: CryptoKey, pub: CryptoKey): ArrayBuffer;

  /**
   * Export a key to a specific format.
   * @param key Key to export (CryptoKey)
   * @param format Format to export ('raw')
   * @returns Serialized key bytes (ArrayBuffer)
   */
  export function exportKey(key: CryptoKey, format: 'raw'): ArrayBuffer;

  /**
   * Import a key from serialized bytes.
   * @param algorithm Algorithm details ({ Name: 'ECDSA', NamedCurve: 'secp256k1' })
   * @param format Format of the input key ('raw')
   * @param keyData Serialized key bytes (ArrayBuffer or Uint8Array)
   * @param keyUsages Array of usages (e.g., ['sign'], ['verify'])
   * @returns Imported CryptoKey
   */
  export function importKey(algorithm: { Name: string; NamedCurve: string }, format: 'raw', keyData: ArrayBuffer | Uint8Array, keyUsages: string[]): CryptoKey;
}
