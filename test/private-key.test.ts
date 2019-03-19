import * as assert from 'assert'
import 'mocha'
import { Scalar } from '../src'
import * as util from '../src/util'

describe('PrivateKey', () => {
    describe('fromBuffer', () => {
        it('works', () => {
            const encoded = util.bufferFromHex('e47d79c74106dbc026a8e672ced54c3f23c7a001a2ef9318be3f338db4edba2d')
            const actual = Scalar.fromBytes(encoded)
            assert.strictEqual(actual, 0xe47d79c74106dbc026a8e672ced54c3f23c7a001a2ef9318be3f338db4edba2dn)
            assert.strictEqual(Scalar.fromBytes(Uint8Array.of(42)), 42n)
        })
    })

    describe('toBuffer', () => {
        it('roundtrips', () => {
            const encoded = 'e47d79c74106dbc026a8e672ced54c3f23c7a001a2ef9318be3f338db4edba2d'
            const key = Scalar.fromBytes(util.bufferFromHex(encoded))
            assert.strictEqual(util.bufferToHex(Scalar.toBytes(key)), encoded)
        })
    })

    // it('cannot exceed curve order', () => {
    //     const scalar = util.secp256k1.n + 1n
    //     assert.throws(() => PrivateKey._fromBigInt(scalar), /invalid privkey/)
    // })
})
