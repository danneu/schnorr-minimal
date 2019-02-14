import * as assert from 'assert'
import { hash } from '../src/sha256'
import { secp256k1 as curve, utf8ToBuffer, bufferToBigInt, bufferFromBigInt } from '../src/util'
import { Point, verify, blindMessage, blindSign, unblind } from '../src'

function verifyTest(): boolean {
    const secretSeed = bufferFromBigInt(randomScalar())
    const noncePriv = randomScalar()
    const signerPriv = randomScalar()
    const noncePub = Point.fromPrivKey(noncePriv)
    const signerPub = Point.fromPrivKey(signerPriv)
    const message = hash(utf8ToBuffer('hello my name is foo and this is a message'))

    // blind
    const [unblinder, blindedMessage] = blindMessage(secretSeed, noncePub, signerPub, message)

    // sign
    const blindedSig = blindSign(signerPriv, noncePriv, blindedMessage)

    // unblind
    const sig = unblind(unblinder, blindedSig)

    // verify
    const verified = verify(signerPub, message, sig)

    return verified
}

describe('blind', () => {
    it('works once', () => {
        assert(verifyTest())
    })

    it('works many times', () => {
        let [yes, no] = [0, 0]
        for (let i = 0; i < 100; i++) {
            const verified = verifyTest()
            if (verified) {
                yes++
            } else {
                no++
            }
        }
        console.log(`yes=${yes} no=${no} total=${yes + no}`)
        assert.equal(no, 0)
    })
})

// HELPERS

function randomScalar(): bigint {
    const { randomFillSync } = require('crypto')
    const buf = new Uint8Array(32)
    randomFillSync(buf)
    return bufferToBigInt(buf) % curve.n
}
