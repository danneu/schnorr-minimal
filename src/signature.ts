import * as assert from 'assert'
import { secp256k1 as curve, powmod, pointFromBuffer } from './util'
import { concatBuffers as concat, bufferToBigInt as int, pointToBuffer, bufferFromBigInt } from './util'
import * as ec from './elliptic'
import hash from './sha256'

// Schnorr Signatures
//
// https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki

function jacobi(x: bigint): bigint {
    return powmod(x, (curve.p - 1n) / 2n, curve.p)
}

export function sign(message: Uint8Array, secret: bigint) {
    const m = message
    const d = secret
    assert.strictEqual(m.length, 32)
    if (d < 1n || d > curve.n - 1n) {
        throw new Error('secret must 1 <= d <= n-1')
    }
    const k0 = int(hash(concat(bufferFromBigInt(d), m))) % curve.n
    if (k0 === 0n) {
        throw new Error('sig failed')
    }
    const R = ec.multiply(curve.g, k0)
    const k = jacobi(R.y) === 1n ? k0 : curve.n - k0
    const e = int(hash(concat(bufferFromBigInt(R.x), pointToBuffer(ec.multiply(curve.g, d)), m))) % curve.n

    const sig = concat(bufferFromBigInt(R.x), bufferFromBigInt((k + e * d) % curve.n))
    return sig
}

export function verify(pubkey: Uint8Array, message: Uint8Array, sig: Uint8Array): boolean {
    assert(pubkey.length === 33)
    assert(message.length === 32)
    assert(sig.length === 64)
    const pk = pubkey
    const m = message

    let P
    try {
        P = pointFromBuffer(pk)
    } catch (err) {
        if (err.message === 'point not on curve') {
            return false
        } else {
            throw err
        }
    }

    const r = int(sig.slice(0, 32))
    if (r >= curve.p) {
        return false
    }

    const s = int(sig.slice(32, 64))
    if (s >= curve.n) {
        return false
    }

    const e = int(hash(concat(bufferFromBigInt(r), pointToBuffer(P), m))) % curve.n
    const R = ec.subtract(ec.multiply(curve.g, s), ec.multiply(P, e))

    if (R === ec.INFINITE_POINT) {
        return false
    } else if (jacobi(R.y) !== 1n) {
        return false
    } else if (R.x !== r) {
        return false
    } else {
        return true
    }
}
