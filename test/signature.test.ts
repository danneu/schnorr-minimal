import * as assert from 'assert'
import 'mocha'
import { Point, Scalar, sign, Signature, util, verify } from '../src'
import { batchVerify } from '../src/signature'
import { bufferFromHex } from '../src/util'

function buffer(hexString: string): Uint8Array {
    return util.bufferFromHex(hexString)
}

function hex(buf: Uint8Array): string {
    return util.bufferToHex(buf)
}

function int(buf: Uint8Array): bigint {
    return util.bufferToBigInt(buf)
}

type SipaVector = {
    privkey?: Scalar
    pubkey: Point | Error // deserialize error
    message: Uint8Array
    signature: Signature
    shouldVerify: boolean
    comment?: string
}

const sipaVectors: SipaVector[] = (() => {
    const { readFileSync } = require('fs')
    const { join } = require('path')
    const { parse } = require('csv/lib/sync')
    // vectors are from https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr/test-vectors.csv
    const text = readFileSync(join(__dirname, './fixtures/sipa-schnorr-test-vectors.csv'), 'utf8')
    const rows = parse(text)

    const vectors = []
    for (let [privkey, pubkey, message, signature, shouldVerify, comment] of rows.slice(1)) {
        privkey = privkey.length ? int(buffer(privkey)) : undefined
        message = buffer(message)
        signature = Signature.fromHex(signature.trim())
        shouldVerify = shouldVerify === 'TRUE'

        try {
            pubkey = Point.fromHex(pubkey)
        } catch (err) {
            pubkey = err
        }

        // given privkey should generate pubkey that matches given pubkey
        if (privkey) {
            const sigActual = sign(message, privkey)
            assert.deepStrictEqual(sigActual, signature)
        }

        vectors.push({
            comment,
            message,
            privkey,
            pubkey,
            shouldVerify,
            signature,
        })
    }

    return vectors
})()

type NodeBipSchnorrVector = {
    privkey?: Scalar
    pubkey: Point | Error
    message: Uint8Array
    signature: Signature
    shouldVerify: boolean
    comment?: string
}

const nodeBipSchnorrVectors: NodeBipSchnorrVector[] = (() => {
    const objects = require('./fixtures/node-bip-schnorr/test-vectors-schnorr.json')
    const vectors = []
    for (const o of objects) {
        let pubkey
        try {
            pubkey = Point.fromHex(o.pk)
        } catch (err) {
            if (err.message === 'point not on curve') {
                pubkey = err.message
            } else {
                pubkey = err
            }
        }
        vectors.push({
            comment: o.comment,
            message: bufferFromHex(o.m),
            privkey: o.d ? Scalar.fromHex(o.d) : undefined,
            pubkey,
            shouldVerify: o.result,
            signature: Signature.fromHex(o.sig),
        })
    }

    return vectors
})()

describe('signature', () => {
    it('works', () => {
        const secret = 0x0000000000000000000000000000000000000000000000000000000000000001n
        const message = buffer('0000000000000000000000000000000000000000000000000000000000000000')
        const expected = buffer(
            '787A848E71043D280C50470E8E1532B2DD5D20EE912A45DBDD2BD1DFBF187EF67031A98831859DC34DFFEEDDA86831842CCD0079E1F92AF177F7F22CC1DCED05'
        )
        const sig = sign(message, secret)
        assert.strictEqual(hex(Signature.toBytes(sig)), hex(expected))

        const pubkey = buffer('0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798')
        assert(verify(Point.fromBytes(pubkey), message, sig))
    })

    it('passes node-bip-schnorr/schnorr vectors', () => {
        // accumulate rows for batch verify
        const pubkeys: Point[] = []
        const messages: Uint8Array[] = []
        const signatures: Signature[] = []

        for (const vec of nodeBipSchnorrVectors) {
            if (vec.pubkey instanceof Error) {
                assert(!vec.shouldVerify, 'should not verify because pubkey was invalid')
                continue
            }

            // test signing
            if (vec.privkey) {
                const sigActual = sign(vec.message, vec.privkey)
                assert.strictEqual(hex(Signature.toBytes(sigActual)), Signature.toHex(vec.signature))
            }

            // test verifying
            const actualVerifies = verify(vec.pubkey, vec.message, vec.signature)
            assert.strictEqual(actualVerifies, vec.shouldVerify)

            // only batch verify the positive vectors
            if (vec.shouldVerify) {
                pubkeys.push(vec.pubkey)
                messages.push(vec.message)
                signatures.push(vec.signature)
            }
        }

        // test batchVerify
        assert.ok(batchVerify(pubkeys, messages, signatures), 'could not batch verify vectors')

        // ensure batchVerify fails
        signatures[0].r += 1n
        assert.ok(!batchVerify(pubkeys, messages, signatures))
    })

    it('passes sipa vectors', () => {
        // accumulate rows for batch verify
        const pubkeys: Point[] = []
        const messages: Uint8Array[] = []
        const signatures: Signature[] = []

        for (const vec of sipaVectors) {
            if (vec.pubkey instanceof Error) {
                assert(!vec.shouldVerify, 'should not verify because pubkey was invalid')
                continue
            }

            // test signing
            if (vec.privkey) {
                const sigActual = sign(vec.message, vec.privkey)
                assert.deepStrictEqual(sigActual, vec.signature)
            }

            // test verifying
            const actualVerifies = verify(vec.pubkey, vec.message, vec.signature)
            assert.strictEqual(actualVerifies, vec.shouldVerify)

            // only batch verify the positive vectors
            if (vec.shouldVerify) {
                pubkeys.push(vec.pubkey)
                messages.push(vec.message)
                signatures.push(vec.signature)
            }
        }

        // test batchVerify
        assert.ok(batchVerify(pubkeys, messages, signatures), 'could not batch verify vectors.csv')

        // ensure batchVerify fails
        signatures[0].r += 1n
        assert.ok(!batchVerify(pubkeys, messages, signatures))
    })
})
