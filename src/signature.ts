import * as assert from 'assert'
import { secp256k1 as curve, powmod, pointFromBuffer } from './util'
import { concatBuffers as concat, bufferToBigInt as int, pointToBuffer, bufferFromBigInt } from './util'
import * as ec from './elliptic'
import { hash } from './sha256'

// Schnorr Signatures
//
// https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki

function jacobi(y: bigint): bigint {
    return powmod(y, (curve.p - 1n) / 2n, curve.p)
}

export class Signature {
    r: bigint // i.e. R.x
    s: bigint

    static fromBuffer(buf: Uint8Array): Signature {
        assert(buf.length === 64, 'encoded signature must be 64 bytes')
        const r = int(buf.slice(0, 32))
        const s = int(buf.slice(32, 64))
        return new Signature(r, s)
    }

    constructor(r: bigint, s: bigint) {
        // assert(r < curve.p, 'r must be < curve.p')
        // assert(s < curve.n, 's must be < curve.n')
        this.r = r
        this.s = s
    }

    toBuffer(): Uint8Array {
        return concat(bufferFromBigInt(this.r), bufferFromBigInt(this.s))
    }
}

export function sign(message: Uint8Array, secret: bigint): Signature {
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

    // nonce
    const k = jacobi(R.y) === 1n ? k0 : curve.n - k0

    // challenge
    const e = int(hash(concat(bufferFromBigInt(R.x), pointToBuffer(ec.multiply(curve.g, d)), m))) % curve.n

    // const sig = concat(bufferFromBigInt(R.x), bufferFromBigInt((k + e * d) % curve.n))
    // return sig
    const s = (k + e * d) % curve.n
    const sig = new Signature(R.x, s)
    return sig
}

export function verify(pubkey: Uint8Array, message: Uint8Array, sig: Signature): boolean {
    assert(pubkey.length === 33, 'pubkey should be 33bytes')
    assert(message.length === 32, 'message must be 32bytes')
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

    const { r, s } = sig

    // TODO: Should fail upon sig construction instead?
    if (r >= curve.p) {
        return false
    }

    if (s >= curve.n) {
        return false
    }

    const e = int(hash(concat(bufferFromBigInt(r), pointToBuffer(P), m))) % curve.n
    const R = ec.subtract(ec.multiply(curve.g, s), ec.multiply(P, e))

    if (R === ec.INFINITE_POINT) {
        return false
    } else if (jacobi(R.y) !== 1n) {
        console.log('verify false. reason: jacobi(R.y) !== 1n')
        return false
    } else if (R.x !== r) {
        console.log('verify false. reason: R.x !== r')
        return false
    } else {
        return true
    }
}
