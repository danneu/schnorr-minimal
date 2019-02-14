# secp256k1-minimal

A simple but naive implementation. Use at your own risk.

## Goals:

1. **Zero dependencies**
2. **Works in web browsers** https://caniuse.com/#search=bigint

## Plans

-   Migrate from bigint to uint8array internally.

## Usage

```javascript
import { Scalar, Point } from 'secp256k1-minimal'

const priv = Scalar.fromHex('0xe47d79c74106dbc026a8e672ced54c3f23c7a001a2ef9318be3f338db4edba2d')
const pub = Point.fromPrivKey(priv)
assert(toHexString(Point.toBytes(pub) === '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')
```
