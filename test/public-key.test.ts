import 'mocha'
import * as assert from 'assert'
import * as util from '../src/util'
import { INFINITE_POINT, pointAdd, pointMultiply } from '../src/elliptic'
import { Point, Scalar } from '../src'

describe('PublicKey', () => {
    describe('fromBuffer', () => {
        it('works', () => {
            const encoded = util.bufferFromHex('031e94bf19fe76d8b905eeee6ffdfdb2a512f50bd7b7518105368c7ac6b0fd866e')
            const actual = Point.fromBytes(encoded)
            assert.deepStrictEqual(actual.x, 0x1e94bf19fe76d8b905eeee6ffdfdb2a512f50bd7b7518105368c7ac6b0fd866en)
        })

        it('privkey -> pubkey -> encode', () => {
            // https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr/test-vectors.csv
            ;[
                [
                    '0000000000000000000000000000000000000000000000000000000000000001',
                    '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
                ],
                [
                    'b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef',
                    '02dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659',
                ],
                [
                    'c90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b14e5c7',
                    '03fac2114c2fbb091527eb7c64ecb11f8021cb45e8e7809d3c0938e4b8c0e5f84b',
                ],
            ].forEach(([privkeyhex, pubkeyhex]) => {
                const privkey = Scalar.fromBytes(util.bufferFromHex(privkeyhex))
                const pubkey = Point.fromPrivKey(privkey)
                assert.strictEqual(util.bufferToHex(Point.toBytes(pubkey)), pubkeyhex)
            })
        })

        it('throws when not on curve', () => {
            const compressedPubkey = util.bufferFromHex(
                '03eefdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a34'
            )

            assert.throws(() => Point.fromBytes(compressedPubkey), /point not on curve/)
        })
    })

    describe('fromPrivateKey', () => {
        it('works', () => {
            ;[
                [
                    0xe47d79c74106dbc026a8e672ced54c3f23c7a001a2ef9318be3f338db4edba2dn,
                    0x031e94bf19fe76d8b905eeee6ffdfdb2a512f50bd7b7518105368c7ac6b0fd866en,
                ],
                [
                    0x1d5d74fec990aeb31a49dacc6a6b985199cc7b807670b6f8099b590718f3f9fan,
                    0x03b7fc65b4444507e5ec8e2ff7e155cdfdead465644fa96caa818221bae977abc8n,
                ],
                [
                    0xd17149773e8fe9d7c9ef97c71c1b2749f280e1dfb0f82c88c61b26e0ceecd461n,
                    0x027aca48b354b794eab5c3a74df8f92e79d93d3d87a1ee3555adb5c9b2852fe20dn,
                ],
            ].forEach(([privScalar, pub]) => {
                const priv = privScalar
                const actual = util.bufferToBigInt(Point.toBytes(Point.fromPrivKey(priv)))
                assert.strictEqual(actual, pub)
            })
        })

        describe('combine', () => {
            it('works', () => {
                const pubs = [
                    '031e94bf19fe76d8b905eeee6ffdfdb2a512f50bd7b7518105368c7ac6b0fd866e',
                    '03b7fc65b4444507e5ec8e2ff7e155cdfdead465644fa96caa818221bae977abc8',
                    '027aca48b354b794eab5c3a74df8f92e79d93d3d87a1ee3555adb5c9b2852fe20d',
                ].map(Point.fromHex)
                const combined = pointAdd(...pubs)
                assert.deepStrictEqual(
                    combined,
                    Point.fromHex('038947870e31d824fc027fb9efd53f8b7446367a5d50b3624075bd2f1089f01791')
                )
            })
        })

        describe('multiply', () => {
            it('works', () => {
                const pub = Point.fromBytes(
                    util.bufferFromHex('027aca48b354b794eab5c3a74df8f92e79d93d3d87a1ee3555adb5c9b2852fe20d')
                )
                ;[
                    // [scalar, expected point]
                    [0n, INFINITE_POINT],
                    [1n, pub],
                    [
                        2n,
                        util.pointFromBuffer(
                            util.bufferFromHex('03a7c1da0e6436c6599c8f1e8790a6f00f42cc86f8ba745ec4ac8333f3a65cd65c')
                        ),
                    ],
                ].forEach(([scalar, expected]) => {
                    const tweak = scalar as bigint
                    const actual = pointMultiply(pub, tweak)
                    assert.deepStrictEqual(actual, expected)
                })
            })
        })

        // https://crypto.stackexchange.com/questions/784/are-there-any-secp256k1-ecdsa-test-examples-available
        it('hxbitcoin', function() {
            this.timeout(20000)
            const { join } = require('path')
            const { readFileSync } = require('fs')
            const re = /k = ([a-z0-9]+)\nx = ([a-z0-9]+)\ny = ([a-z0-9]+)/i
            let text = readFileSync(join(__dirname, './fixtures/hxbitcoin.txt'), 'utf8')
            const fixtures = []
            for (const part of text.split('\n\n')) {
                let [, k, x, y] = part.match(re)
                k = BigInt(k)
                x = util.bufferToBigInt(util.bufferFromHex(x))
                y = util.bufferToBigInt(util.bufferFromHex(y))
                fixtures.push({ k, x, y })
            }

            for (const { k, x, y } of fixtures) {
                const privkey = k
                const pubkey = Point.fromPrivKey(privkey)
                assert.deepStrictEqual(pubkey, { x, y }, `k=${k}`)
            }
        })
    })
})
