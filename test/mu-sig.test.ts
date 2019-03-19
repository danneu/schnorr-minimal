import * as assert from 'assert'
import { muSig, Point, util, verify } from '../src'
import { hash } from '../src/sha256'
import * as helpers from './helpers'

describe('mu-sig', () => {
    describe('pubkeyCombine', () => {
        const testVectors = require('./fixtures/bip-schnorr/test-vectors-mu-sig.json')
        for (const vec of testVectors) {
            it(`can combine pubkeys into ${vec.pubKeyCombined}`, () => {
                const pubkeys = vec.pubKeys.map(Point.fromHex)
                const pubkeyCombined = muSig.pubkeyCombine(pubkeys)
                assert.strictEqual(Point.toHex(pubkeyCombined), vec.pubKeyCombined)
            })
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
