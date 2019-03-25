import * as assert from 'assert'
import { muSig, Point, Scalar, Signature, verify } from '../src'
import { bufferFromHex } from '../src/util'
import * as helpers from './helpers'

type NodeBipSchnorr_MuSigVector = {
    privkeys: Scalar[]
    pubkeys: Point[]
    pubkeyCombined: Point
    message: Uint8Array
    signature: Signature
}

const muSigVectors: NodeBipSchnorr_MuSigVector[] = (() => {
    const objs = require('./fixtures/node-bip-schnorr/test-vectors-mu-sig.json')
    const vectors = []
    for (const o of objs) {
        vectors.push({
            message: bufferFromHex(o.message),
            privkeys: o.privKeys.map(Scalar.fromHex),
            pubkeyCombined: Point.fromHex(o.pubKeyCombined),
            pubkeys: o.pubKeys.map(Point.fromHex),
            signature: Signature.fromHex(o.signature),
        })
    }
    return vectors
})()

describe('mu-sig', () => {
    it(`passes ${muSigVectors.length} musig vectors`, () => {
        for (const vec of muSigVectors) {
            // test that our pubkeyCombine matches vector's pubkeyCombine
            const actualPubkeyCombined = muSig.pubkeyCombine(vec.pubkeys)
            assert.deepStrictEqual(actualPubkeyCombined, vec.pubkeyCombined)

            // given vector should verify
            assert.ok(verify(vec.pubkeyCombined, vec.message, vec.signature))

            // our sign() signature should verify too
            const actualSig = muSig.signNoninteractively(vec.privkeys, vec.message)
            assert.ok(verify(vec.pubkeyCombined, vec.message, actualSig))
        }
    })

    describe('sign', () => {
        it('can aggregate random qty of random signers', () => {
            const xs = (() => {
                const keyQty = helpers.randomInt(1, 100)
                console.log(`testing with ${keyQty} signers`)
                const keys = []
                for (let i = 0; i < keyQty; i++) {
                    keys.push(helpers.randomPrivkey())
                }
                return keys
            })()
            const Xcom = muSig.pubkeyCombine(xs.map(Point.fromPrivKey))
            const message = helpers.randomBuffer(32)
            const signature = muSig.signNoninteractively(xs, message)
            assert.ok(verify(Xcom, message, signature))
            assert.ok(!verify(Xcom, helpers.randomBuffer(32), signature))
        })

        it('works with single signer', () => {
            const x1 = helpers.randomPrivkey()
            const Xcom = muSig.pubkeyCombine([Point.fromPrivKey(x1)])
            const message = helpers.randomBuffer(32)
            const signature = muSig.signNoninteractively([x1], message)
            assert.ok(verify(Xcom, message, signature), 'combined pubkey should verify')
            assert.ok(!verify(Point.fromPrivKey(x1), message, signature), 'un-combined pubkey should not verify')
        })

        it('throws if input collections are empty', () => {
            assert.throws(() => muSig.pubkeyCombine([]))
            assert.throws(() => muSig.signNoninteractively([], new Uint8Array()))
        })
    })
})
