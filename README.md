# secp256k1-minimal

**Warning**: This library currently uses bigints and is not timing-safe.

## Goals:

1. **Zero dependencies**
2. **Works in web browsers**. Warning: Depends on native bigint (https://caniuse.com/#search=bigint)

## Plans

-   Migrate from bigint to uint8array internally.

## Usage

```javascript
import { PrivateKey, PublicKey } from 'secp256k1-minimal'

const scalar = new Uint8Array('0xe47d79c74106dbc026a8e672ced54c3f23c7a001a2ef9318be3f338db4edba2d')
const priv = PrivateKey.fromBuffer(scalar)
const pub = PublicKey.fromPrivateKey(priv)
assert(
    toHexString(pub.toBuffer()) ===
        '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
)
```
