package secp256k1

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	keys, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	if keys.PrivateKey == nil || keys.PublicKey == nil {
		t.Fatal("Generated keys are nil")
	}

	if keys.PrivateKey.privKey == nil || keys.PublicKey.pubKey == nil {
		t.Fatal("Internal key objects missing")
	}

	if keys.PrivateKey.Type != PrivateCryptoKeyType || keys.PublicKey.Type != PublicCryptoKeyType {
		t.Fatal("Key types incorrect")
	}
}

func TestSignVerify(t *testing.T) {
	keys, _ := GenerateKey()
	message := []byte("Hello k6/x/secp256k1!")

	sig, err := Sign(keys.PrivateKey, message)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	ok, err := Verify(keys.PublicKey, message, sig)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !ok {
		t.Fatal("Signature verification failed")
	}

	// Verify with modified message fails
	ok, _ = Verify(keys.PublicKey, []byte("tampered"), sig)
	if ok {
		t.Fatal("Signature verification should fail for tampered message")
	}
}

func TestExportImportRawKey(t *testing.T) {
	keys, _ := GenerateKey()

	privBytes, err := exportRawKey(keys.PrivateKey)
	if err != nil {
		t.Fatalf("exportRawKey failed: %v", err)
	}

	pubBytes, err := exportRawKey(keys.PublicKey)
	if err != nil {
		t.Fatalf("exportRawKey (public) failed: %v", err)
	}

	privKey, _, keyType, err := ImportRawKey(privBytes)
	if err != nil {
		t.Fatalf("ImportRawKey private failed: %v", err)
	}
	if keyType != PrivateCryptoKeyType {
		t.Fatal("Imported private key type mismatch")
	}
	if !bytes.Equal(privBytes, privKey.Serialize()) {
		t.Fatal("Private key bytes mismatch after import")
	}

	_, pubKey2, keyType, err := ImportRawKey(pubBytes)
	if err != nil {
		t.Fatalf("ImportRawKey public failed: %v", err)
	}
	if keyType != PublicCryptoKeyType {
		t.Fatal("Imported public key type mismatch")
	}
	if !bytes.Equal(pubBytes, pubKey2.SerializeCompressed()) {
		t.Fatal("Public key bytes mismatch after import")
	}
}

func TestJWKExportImport(t *testing.T) {
    // Generate key pair
    keys, err := GenerateKey()
    if err != nil {
        t.Fatalf("GenerateKey failed: %v", err)
    }

    // Ensure private key includes the public key for export
    keys.PrivateKey.pubKey = keys.PublicKey.pubKey

    // Export private key as JWK
    jwkBytes, err := exportJWKKey(keys.PrivateKey)
    if err != nil {
        t.Fatalf("exportJWKKey failed: %v", err)
    }

    // Import the JWK back
    privKey, pubKey, keyType, err := ImportJWKKey(jwkBytes)
    if err != nil {
        t.Fatalf("ImportJWKKey failed: %v", err)
    }

    if keyType != PrivateCryptoKeyType {
        t.Fatal("Imported JWK key type mismatch")
    }

    // Compare private keys
    if !bytes.Equal(privKey.Serialize(), keys.PrivateKey.privKey.Serialize()) {
        t.Fatal("Private key mismatch after JWK import")
    }

    // Compare public keys
    if !bytes.Equal(pubKey.SerializeCompressed(), keys.PublicKey.pubKey.SerializeCompressed()) {
        t.Fatal("Public key mismatch after JWK import")
    }
}


func TestDeriveBits(t *testing.T) {
	aliceKeys, _ := GenerateKey()
	bobKeys, _ := GenerateKey()

	secret1, err := DeriveBits(aliceKeys.PrivateKey, bobKeys.PublicKey)
	if err != nil {
		t.Fatalf("DeriveBits failed: %v", err)
	}

	secret2, err := DeriveBits(bobKeys.PrivateKey, aliceKeys.PublicKey)
	if err != nil {
		t.Fatalf("DeriveBits failed: %v", err)
	}

	if !bytes.Equal(secret1, secret2) {
		t.Fatal("Derived secrets do not match")
	}

	// Optionally, print base64 encoded secret for debugging
	t.Logf("Shared secret: %s", base64.StdEncoding.EncodeToString(secret1))
}
