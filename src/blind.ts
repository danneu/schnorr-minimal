import * as assert from 'assert'
import { Point, pointAdd as add, pointMultiply as mul, scalarAdd, scalarMultiply } from './elliptic'
import { hash, hmac } from './sha256'
import { Signature } from './signature'
import {
    bufferFromBigInt,
    bufferToBigInt,
    concatBuffers as concat,
    curve,
    jacobi,
    pointToBuffer,
    utf8ToBuffer,
} from './util'

export type BlindedMessage = { c: bigint /* c = challenge */ }
export type Unblinder = { alpha: bigint; r: bigint /* R.x */ }
export type BlindedSignature = { s: bigint }

export function blindMessage(
    secret: Uint8Array,
    nonce: Point,
    signer: Point,
    message: Uint8Array
): [Unblinder, BlindedMessage] {
    assert.strictEqual(message.length, 32, 'message must have 32 length')
    const R = nonce
    const P = signer

    const alpha = bufferToBigInt(
        hmac(utf8ToBuffer('alpha'), [secret, pointToBuffer(nonce), pointToBuffer(signer), message])
    )

    // spin beta until we find quadratic residue
    let retry = 0
    let beta
    let RPrime
    while (true) {
        beta = bufferToBigInt(
            hmac(utf8ToBuffer('beta'), [
                secret,
                pointToBuffer(nonce),
                pointToBuffer(signer),
                message,
                Uint8Array.of(retry),
            ])
        )

        RPrime = add(R, mul(curve.g, alpha), mul(P, beta))

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

    return [{ alpha, r: RPrime.x }, { c }]
}

export function blindSign(signer: bigint, nonce: bigint, { c }: BlindedMessage): BlindedSignature {
    const x = signer
    const k = nonce

    const s = scalarAdd(k, scalarMultiply(c, x))
    return { s }
}

export function unblind({ alpha, r }: Unblinder, blindedSig: BlindedSignature): Signature {
    const s = scalarAdd(blindedSig.s, alpha)
    return { r, s }
}
