import { Point, multiply as mul, add, subtract } from './elliptic'
import { Signature } from './signature'
import * as assert from 'assert'
import {
    utf8ToBuffer,
    concatBuffers as concat,
    secp256k1 as curve,
    bufferToBigInt,
    bufferFromBigInt,
    powmod,
    pointToBuffer,
} from './util'
import { hash, hmac } from './sha256'

export class BlindedMessage {
    challenge: bigint

    constructor(challenge: bigint) {
        this.challenge = challenge
    }
}

export class Unblinder {
    alpha: bigint
    r: bigint // R.x

    constructor(alpha: bigint, r: bigint) {
        this.alpha = alpha
        this.r = r
    }
}

export class BlindedSignature {
    s: bigint

    constructor(s: bigint) {
        this.s = s
    }
}

const G = curve.g

export function blindMessage(
    secret: bigint,
    nonce: Point,
    signer: Point,
    message: Uint8Array
): [Unblinder, BlindedMessage] {
    const R = nonce
    const P = signer

    const alpha = bufferToBigInt(
        hmac(utf8ToBuffer('alpha'), [bufferFromBigInt(secret), pointToBuffer(nonce), pointToBuffer(signer), message])
    )

    // spin beta until we find quadratic residue
    let retry = 0
    let beta
    let RPrime
    while (true) {
        beta = bufferToBigInt(
            hmac(utf8ToBuffer('beta'), [
                bufferFromBigInt(secret),
                pointToBuffer(nonce),
                pointToBuffer(signer),
                message,
                Uint8Array.of(retry),
            ])
        )

        RPrime = add(R, mul(G, alpha), mul(P, beta))

        if (jacobi(RPrime.y) === 1n) {
            break
        } else {
            retry++
        }
    }

    // the challenge
    const cPrime = bufferToBigInt(hash(concat(bufferFromBigInt(RPrime.x), pointToBuffer(P), message))) % curve.n

    // the blinded challenge
    const c = scalarAdd(cPrime, beta)

    return [new Unblinder(alpha, RPrime.x), new BlindedMessage(c)]
}

export function blindSign(signer: bigint, nonce: bigint, blindedMessage: BlindedMessage): BlindedSignature {
    const c = blindedMessage.challenge
    const x = signer
    const k = nonce

    const s = scalarAdd(k, scalarMultiply(c, x))
    return new BlindedSignature(s)
}

export function unblind({ alpha, r }: Unblinder, blindedSig: BlindedSignature): Signature {
    let s = scalarAdd(blindedSig.s, alpha)
    return new Signature(r, s)
}

// TEMP FUNCTIONS -- will be removed

function jacobi(y: bigint): bigint {
    return powmod(y, (curve.p - 1n) / 2n, curve.p)
}

function scalarMultiply(a: bigint, b: bigint): bigint {
    return (a * b) % curve.n
}

function scalarAdd(a: bigint, b: bigint): bigint {
    return (a + b) % curve.n
}
