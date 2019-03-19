import * as assert from 'assert'
import { muSig, Point, util, verify, Scalar, Signature } from '../src'
import { hash } from '../src/sha256'
import * as helpers from './helpers'
import { bufferFromHex } from '../src/util'

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
            privkeys: o.privKeys.map(Scalar.fromHex),
            pubkeys: o.pubKeys.map(Point.fromHex),
            pubkeyCombined: Point.fromHex(o.pubKeyCombined),
            message: bufferFromHex(o.message),
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
            const actualSig = muSig.sign(vec.privkeys, vec.message)
            assert.ok(verify(vec.pubkeyCombined, vec.message, actualSig))
        }
    })

    describe('multi-signer signature', () => {
        it('does verify', () => {
            const message = hash(util.utf8ToBuffer('test message'))
            const privateKeys = (() => {
                const keyQty = helpers.randomInt(1, 100)
                console.log(`testing with ${keyQty} signers`)
                const keys = []
                for (let i = 0; i < keyQty; i++) {
                    keys.push(helpers.randomPrivkey())
                }
                return keys
            })()

            const pubkeyCombined = muSig.pubkeyCombine(privateKeys.map(Point.fromPrivKey))
            const signature = muSig.sign(privateKeys, message)
            assert.ok(verify(pubkeyCombined, message, signature))
        })

        it('works with single signer', () => {
            const privkey = helpers.randomPrivkey()
            const pubkeyCombined = muSig.pubkeyCombine([Point.fromPrivKey(privkey)])
            const message = hash(util.utf8ToBuffer('hello'))
            const signature = muSig.sign([privkey], message)

            // Works with combined pubkey
            assert.ok(verify(pubkeyCombined, message, signature))

            // Does NOT work with uncombined pubkey
            assert.ok(
                !verify(Point.fromPrivKey(privkey), message, signature),
                'un-combined pubkey does not verify mu-sig'
            )
        })

        it('throws if input collections are empty', () => {
            assert.throws(() => muSig.pubkeyCombine([]))
            assert.throws(() => muSig.sign([], new Uint8Array()))
        })
    })
})
