package xk6cryptosecp256k1

// This package exists so the module root (github.com/exterminatorz/xk6-crypto-secp256k1)
// can be imported directly by xk6's --with flag. It blank-imports the real
// implementation in the `secp256k1` subpackage which performs the actual
// module registration in its init().

import _ "github.com/exterminatorz/xk6-crypto-secp256k1/secp256k1"
