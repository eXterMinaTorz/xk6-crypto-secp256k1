package secp256k1

import (
	"crypto/sha256"
	"fmt"

	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"go.k6.io/k6/js/modules"
)

// Typed algorithm structures matching the WebCrypto-style shape
type KeyAlgorithm struct {
	Algorithm interface{} `json:"algorithm" js:"algorithm"`
	Name      string      `json:"name" js:"name"`
}

type EcKeyAlgorithm struct {
	KeyAlgorithm KeyAlgorithm `json:"key_algorithm" js:"key_algorithm"`
	Algorithm    interface{}  `json:"algorithm" js:"algorithm"`
	Name         string       `json:"name" js:"name"`
	NamedCurve   string       `json:"namedCurve" js:"namedCurve"`
}

// CryptoKeyType represents the key type exposed to JS
type CryptoKeyType string

const (
	UnknownCryptoKeyType CryptoKeyType = "unknown"
	PrivateCryptoKeyType CryptoKeyType = "private"
	PublicCryptoKeyType  CryptoKeyType = "public"
)

// CryptoKeyUsage represents allowed usages
type CryptoKeyUsage string

const (
	SignCryptoKeyUsage       CryptoKeyUsage = "sign"
	VerifyCryptoKeyUsage     CryptoKeyUsage = "verify"
	DeriveBitsCryptoKeyUsage CryptoKeyUsage = "deriveBits"
	DeriveKeyCryptoKeyUsage  CryptoKeyUsage = "deriveKey"
)

// CryptoKey simulates subtlecrypto's CryptoKey
type CryptoKey struct {
	Type        CryptoKeyType    `js:"type" json:"type"`
	Extractable bool             `js:"extractable" json:"extractable"`
	Algorithm   any              `js:"algorithm" json:"algorithm"`
	Usages      []CryptoKeyUsage `js:"usages" json:"usages"`

	privKey *secp256k1.PrivateKey // used only in private key objects
	pubKey  *secp256k1.PublicKey  // used only in public key objects
}

// CryptoKeyPair matches WebCrypto's shape for generated key pairs.
type CryptoKeyPair struct {
	PrivateKey *CryptoKey `js:"privateKey" json:"privateKey"`
	PublicKey  *CryptoKey `js:"publicKey" json:"publicKey"`
}

type Exporter struct{}

type KeyFormat string

const (
	RawKeyFormat   KeyFormat = "raw"
	SpkiKeyFormat  KeyFormat = "spki"
	Pkcs8KeyFormat KeyFormat = "pkcs8"
	JwkKeyFormat   KeyFormat = "jwk"
)

// EllipticCurveKind denotes ECDSA vs ECDH
type EllipticCurveKind string

const (
	ECDSA EllipticCurveKind = "ECDSA"
	ECDH  EllipticCurveKind = "ECDH"
)

// EcKeyImportParams mirrors WebCrypto import parameters for EC keys
type EcKeyImportParams struct {
	Name       EllipticCurveKind
	NamedCurve string
	Algorithm  any
}


func (e *Exporter) Exports() modules.Exports {
	named := map[string]interface{}{
		"generateKey": GenerateKey,
		"importKey":   ImportKey,
		"exportKey":   ExportKey,
		"sign":        Sign,
		"verify":      Verify,
		"deriveBits":  DeriveBits,
	}
	return modules.Exports{Named: named}
}

// NewModuleInstance makes Exporter implement modules.Module so k6 will
// call Exports() via the Module/Instance contract.
func (e *Exporter) NewModuleInstance(vu modules.VU) modules.Instance {
	return e
}

func init() {
	// Register the module so k6 can import it as k6/x/secp256k1
	modules.Register("k6/x/secp256k1", new(Exporter))
}

var allowedUsagesPrivate = []CryptoKeyUsage{
	SignCryptoKeyUsage,
	DeriveBitsCryptoKeyUsage,
	DeriveKeyCryptoKeyUsage,
}

var allowedUsagesPublic = []CryptoKeyUsage{
	VerifyCryptoKeyUsage,
	DeriveBitsCryptoKeyUsage,
}

func filterUsages(requested []CryptoKeyUsage, keyType CryptoKeyType) []CryptoKeyUsage {
	var allowed []CryptoKeyUsage
	var allowedSet map[CryptoKeyUsage]struct{}

	if keyType == PrivateCryptoKeyType {
		allowedSet = make(map[CryptoKeyUsage]struct{})
		for _, u := range allowedUsagesPrivate {
			allowedSet[u] = struct{}{}
		}
	} else if keyType == PublicCryptoKeyType {
		allowedSet = make(map[CryptoKeyUsage]struct{})
		for _, u := range allowedUsagesPublic {
			allowedSet[u] = struct{}{}
		}
	} else {
		return nil
	}

	for _, u := range requested {
		if _, ok := allowedSet[u]; ok {
			allowed = append(allowed, u)
		}
	}
	return allowed
}

// GenerateKey generates a secp256k1 key pair
// Returns a single object with "privateKey" and "publicKey" entries to match
// the requested JSON shape.
func GenerateKey() (*CryptoKeyPair, error) {
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	pub := priv.PubKey()

	algorithmObj := EcKeyAlgorithm{
		KeyAlgorithm: KeyAlgorithm{Algorithm: map[string]string{"name": "ECDSA"}, Name: "ECDSA"},
		Algorithm:    map[string]string{"name": "ECDSA"},
		Name:         "ECDSA",
		NamedCurve:   "secp256k1",
	}

	privateKeyObj := &CryptoKey{
		Algorithm:   algorithmObj,
		Extractable: true,
		Type:        PrivateCryptoKeyType,
		Usages:      filterUsages([]CryptoKeyUsage{SignCryptoKeyUsage}, PrivateCryptoKeyType),
		privKey:     priv,
		// pubKey omitted
	}

	publicKeyObj := &CryptoKey{
		Algorithm:   algorithmObj,
		Extractable: true,
		Type:        PublicCryptoKeyType,
		Usages:      filterUsages([]CryptoKeyUsage{VerifyCryptoKeyUsage}, PublicCryptoKeyType),
		pubKey:      pub,
	}

	return &CryptoKeyPair{
		PrivateKey: privateKeyObj,
		PublicKey:  publicKeyObj,
	}, nil
}

// KeyFormat represents import/export key formats

func ImportPKCS8Key(keyData []byte) (*secp256k1.PrivateKey, *secp256k1.PublicKey, CryptoKeyType, error) {
	if block, _ := pem.Decode(keyData); block != nil {
		keyData = block.Bytes
	}

	var pkcs8 struct {
		Version    int
		Algorithm  struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.RawValue `asn1:"optional"`
		}
		PrivateKey []byte
	}

	if _, err := asn1.Unmarshal(keyData, &pkcs8); err != nil {
		return nil, nil, UnknownCryptoKeyType, fmt.Errorf("failed to parse PKCS8: %w", err)
	}

	if !pkcs8.Algorithm.Algorithm.Equal(oidSecp256k1) {
		return nil, nil, UnknownCryptoKeyType, errors.New("unsupported PKCS8 OID, expected secp256k1")
	}

	if len(pkcs8.PrivateKey) != 32 {
		return nil, nil, UnknownCryptoKeyType, errors.New("invalid private key length in PKCS8")
	}

	priv := secp256k1.PrivKeyFromBytes(pkcs8.PrivateKey)
	return priv, nil, PrivateCryptoKeyType, nil
}

func ImportRawKey(raw []byte) (*secp256k1.PrivateKey, *secp256k1.PublicKey, CryptoKeyType, error) {
	switch len(raw) {
	case 32:
		// Raw private key
		priv := secp256k1.PrivKeyFromBytes(raw)
		return priv, priv.PubKey(), PrivateCryptoKeyType, nil
	case 33, 65:
		// Raw public key
		pub, err := secp256k1.ParsePubKey(raw)
		if err != nil {
			return nil, nil, UnknownCryptoKeyType, err
		}
		return nil, pub, PublicCryptoKeyType, nil
	default:
		return nil, nil, UnknownCryptoKeyType, errors.New("invalid raw secp256k1 key length")
	}
}

var oidSecp256k1 = asn1.ObjectIdentifier{1, 3, 132, 0, 10}
func ImportSPKIKey(spki []byte) (*secp256k1.PrivateKey, *secp256k1.PublicKey, CryptoKeyType, error) {
	if block, _ := pem.Decode(spki); block != nil {
		spki = block.Bytes
	}

	var info struct {
		Algorithm struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.RawValue `asn1:"optional"`
		}
		SubjectPublicKey asn1.BitString
	}

	if _, err := asn1.Unmarshal(spki, &info); err != nil {
		return nil, nil, UnknownCryptoKeyType, fmt.Errorf("failed to parse SPKI: %w", err)
	}

	if !info.Algorithm.Algorithm.Equal(oidSecp256k1) {
		return nil, nil, UnknownCryptoKeyType, errors.New("unsupported SPKI OID, expected secp256k1")
	}

	pub, err := secp256k1.ParsePubKey(info.SubjectPublicKey.Bytes)
	if err != nil {
		return nil, nil, UnknownCryptoKeyType, fmt.Errorf("failed to parse secp256k1 public key: %w", err)
	}

	return nil, pub, PublicCryptoKeyType, nil
}

func ImportJWKKey(jwkJSON []byte) (*secp256k1.PrivateKey, *secp256k1.PublicKey, CryptoKeyType, error) {
	var jwk struct {
		Kty string `json:"kty"`           // must be "EC"
		Crv string `json:"crv"`           // must be "secp256k1"
		X   string `json:"x,omitempty"`   // base64url
		Y   string `json:"y,omitempty"`   // base64url
		D   string `json:"d,omitempty"`   // base64url, private scalar
	}

	if err := json.Unmarshal(jwkJSON, &jwk); err != nil {
		return nil, nil, UnknownCryptoKeyType, fmt.Errorf("failed to parse JWK: %w", err)
	}

	if jwk.Kty != "EC" || jwk.Crv != "secp256k1" {
		return nil, nil, UnknownCryptoKeyType, errors.New("unsupported JWK type or curve")
	}

	// Private key
	if jwk.D != "" {
		rawD, err := base64.RawURLEncoding.DecodeString(jwk.D)
		if err != nil {
			return nil, nil, UnknownCryptoKeyType, fmt.Errorf("failed to decode d: %w", err)
		}
		priv := secp256k1.PrivKeyFromBytes(rawD)
		return priv, priv.PubKey(), PrivateCryptoKeyType, nil
	}

	// Public-only key
	if jwk.X != "" && jwk.Y != "" {
		rawX, err := base64.RawURLEncoding.DecodeString(jwk.X)
		if err != nil {
			return nil, nil, UnknownCryptoKeyType, fmt.Errorf("failed to decode x: %w", err)
		}
		rawY, err := base64.RawURLEncoding.DecodeString(jwk.Y)
		if err != nil {
			return nil, nil, UnknownCryptoKeyType, fmt.Errorf("failed to decode y: %w", err)
		}

		// Ensure both X and Y are 32 bytes by left-padding
		xPadded := make([]byte, 32)
		yPadded := make([]byte, 32)
		copy(xPadded[32-len(rawX):], rawX)
		copy(yPadded[32-len(rawY):], rawY)

		rawPub := append([]byte{0x04}, append(xPadded, yPadded...)...)
		pub, err := secp256k1.ParsePubKey(rawPub)
		if err != nil {
			return nil, nil, UnknownCryptoKeyType, fmt.Errorf("failed to parse public key: %w", err)
		}
		return nil, pub, PublicCryptoKeyType, nil
	}

	return nil, nil, UnknownCryptoKeyType, errors.New("invalid JWK: missing key material")
}


// ImportKey implements flexible EC key import similar to WebCrypto's pattern.
func ImportKey(e EcKeyImportParams, format KeyFormat, keyData []byte, requestedUsages []CryptoKeyUsage) (*CryptoKey, error) {
	type importFnType func(keyData []byte) (*secp256k1.PrivateKey, *secp256k1.PublicKey, CryptoKeyType, error)
	var importFn importFnType

	switch format {
	case Pkcs8KeyFormat:
		importFn = ImportPKCS8Key
	case RawKeyFormat:
		importFn = ImportRawKey
	case SpkiKeyFormat:
		importFn = ImportSPKIKey
	case JwkKeyFormat:
		importFn = ImportJWKKey
	default:
		return nil, errors.New("unsupported key format")
	}

	priv, pub, keyType, err := importFn(keyData)
	if err != nil {
		return nil, err
	}

	// return CryptoKey with internal handle set (pubKey)
	return &CryptoKey{
		Algorithm: EcKeyAlgorithm{
			KeyAlgorithm: KeyAlgorithm{
				Algorithm: e.Algorithm,
			},
			NamedCurve: e.NamedCurve,
		},
		Type:   keyType,
		privKey: priv,
		pubKey: pub,
		Usages: filterUsages(requestedUsages, keyType),
	}, nil
}

func exportPKCS8Key(key *CryptoKey) ([]byte, error) {
	if key.privKey == nil {
		return nil, errors.New("cannot export PKCS8: private key is missing")
	}

	privBytes := key.privKey.Serialize() // 32 bytes scalar

	// Build PKCS8 structure manually
	pkcs8 := struct {
		Version    int
		Algorithm  struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.RawValue `asn1:"optional"`
		}
		PrivateKey []byte
	}{
		Version: 0,
		Algorithm: struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.RawValue `asn1:"optional"`
		}{
			Algorithm: oidSecp256k1,
		},
		PrivateKey: privBytes,
	}

	der, err := asn1.Marshal(pkcs8)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}), nil
}

func exportRawKey(key *CryptoKey) ([]byte, error) {
	if key.privKey != nil {
		return key.privKey.Serialize(), nil
	}
	if key.pubKey != nil {
		return key.pubKey.SerializeCompressed(), nil
	}
	return nil, errors.New("no key data to export")
}

func exportSPKIKey(key *CryptoKey) ([]byte, error) {
	if key.pubKey == nil {
		return nil, errors.New("no public key to export")
	}

	spki := struct {
		Algorithm        struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.RawValue `asn1:"optional"`
		}
		SubjectPublicKey asn1.BitString
	}{
		Algorithm: struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.RawValue `asn1:"optional"`
		}{
			Algorithm: oidSecp256k1,
		},
		SubjectPublicKey: asn1.BitString{Bytes: key.pubKey.SerializeCompressed()},
	}

	spkiBytes, err := asn1.Marshal(spki)
	if err != nil {
		return nil, err
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: spkiBytes,
	}
	return pem.EncodeToMemory(pemBlock), nil
}

func exportJWKKey(key *CryptoKey) ([]byte, error) {
	if key.pubKey == nil {
		return nil, errors.New("no key to export")
	}

	xBytes := key.pubKey.X().Bytes()
	yBytes := key.pubKey.Y().Bytes()

	// Ensure both coordinates are 32 bytes by left-padding with zeros
	xPadded := make([]byte, 32)
	yPadded := make([]byte, 32)
	copy(xPadded[32-len(xBytes):], xBytes)
	copy(yPadded[32-len(yBytes):], yBytes)

	jwk := make(map[string]string)
	jwk["kty"] = "EC"
	jwk["crv"] = "secp256k1"
	jwk["x"] = base64.RawURLEncoding.EncodeToString(xPadded)
	jwk["y"] = base64.RawURLEncoding.EncodeToString(yPadded)

	if key.privKey != nil {
		dBytes := key.privKey.Serialize()
		jwk["d"] = base64.RawURLEncoding.EncodeToString(dBytes)
	}

	return json.Marshal(jwk)
}

// ExportKey exports a CryptoKey into the requested KeyFormat.
// Supports Raw for public keys (returns []byte). Other formats are TODO.
func ExportKey(key *CryptoKey, format KeyFormat) ([]byte, error) {
	// Define function signature for format-specific exporters
	type exportFnType func(*CryptoKey) ([]byte, error)

	var exportFn exportFnType

	switch format {
	case Pkcs8KeyFormat:
		exportFn = exportPKCS8Key
	case RawKeyFormat:
		exportFn = exportRawKey
	case SpkiKeyFormat:
		exportFn = exportSPKIKey
	case JwkKeyFormat:
		exportFn = exportJWKKey
	default:
		return nil, errors.New("unsupported export format")
	}

	return exportFn(key)
}

// Sign signs data using a private key
func Sign(key *CryptoKey, message []byte) ([]byte, error) {
	if key.privKey == nil {
		return nil, errors.New("cannot sign: private key missing")
	}
	// Sign the message
	msgHash := sha256.Sum256(message)
	sig := ecdsa.Sign(key.privKey, msgHash[:])

	// Return DER-encoded signature (r||s in DER format)
	return sig.Serialize(), nil
}

// Verify verifies a signature against a message and public key
func Verify(key *CryptoKey, message, signature []byte) (bool, error) {
	if key.pubKey == nil {
		return false, errors.New("cannot verify: public key missing")
	}

	sig, err := ecdsa.ParseDERSignature(signature)
	if err != nil {
		return false, fmt.Errorf("invalid signature: %w", err)
	}
	msgHash := sha256.Sum256(message)
	return sig.Verify(msgHash[:], key.pubKey), nil
}

// DeriveBits computes a shared secret (ECDH)
func DeriveBits(priv *CryptoKey, pub *CryptoKey) ([]byte, error) {
	var a *secp256k1.PrivateKey
	var b *secp256k1.PublicKey

	if priv.privKey != nil {
		a = priv.privKey
	}

	if pub.pubKey != nil {
		b = pub.pubKey
	}

	if a == nil || b == nil {
		return nil, errors.New("keys missing")
	}
	secret := secp256k1.GenerateSharedSecret(a, b)
	return secret, nil
}


