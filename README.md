# schnorr-minimal ![build status](https://api.travis-ci.org/danneu/schnorr-minimal.svg?branch=master)

A simple but naive Typescript implementation of Schnorr signatures on the secp256k1 elliptical curve.

Use at your own risk.

## Features

-   Schnorr signatures ([bip-schnorr](https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki))
-   Multi signatures ([MuSig](https://blockstream.com/2018/01/23/musig-key-aggregation-schnorr-signatures/))
-   Blind signatures
-   Jacobian optimization

## Goals

1. Zero dependencies
2. Works in Node and web browsers (https://caniuse.com/#feat=bigint 💀)

## Plans

-   Migrate from bigint to uint8array internally.

## Usage

(TODO) See tests for now.

```javascript
import { Scalar, Point } from 'schnorr-minimal'

const priv = Scalar.fromHex('e47d79c74106dbc026a8e672ced54c3f23c7a001a2ef9318be3f338db4edba2d')
const pub = Point.fromPrivKey(priv)
assert(Point.toHex(pub) === '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')
```
