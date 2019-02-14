import * as ec from '../src/elliptic'
import { hash } from '../src/sha256'
import { powmod, secp256k1 as curve, utf8ToBuffer, bufferToBigInt } from '../src/util'
import { unblind, blindSign, blindMessage } from '../src/blind'
import { verify } from '../src/signature'
import PublicKey from '../src/public-key'
import * as assert from 'assert'

function verifyTest(): boolean {
    const secretSeed = randomScalar()
    const noncePriv = randomScalar()
    const signerPriv = randomScalar()
    const noncePub = ec.multiply(curve.g, noncePriv)
    const signerPub = ec.multiply(curve.g, signerPriv)
    const message = hash(utf8ToBuffer('hello my name is foo and this is a message'))

    // blind
    const [unblinder, blindedMessage] = blindMessage(secretSeed, noncePub, signerPub, message)

    // sign
    const blindedSig = blindSign(signerPriv, noncePriv, blindedMessage)

    // unblind
    const sig = unblind(unblinder, blindedSig)

    // verify
    const verified = verify(PublicKey._fromPoint(signerPub).toBuffer(), message, sig)

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
