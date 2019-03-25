// https://github.com/ElementsProject/secp256k1-zkp/blob/secp256k1-zkp/src/tests.c
import * as assert from 'assert'
import { Point, util as u, verify } from '../../src'
import { Scalar, scalarAdd, scalarInverse, scalarMultiply, scalarNegate } from '../../src/elliptic'
import { hash, hmac } from '../../src/sha256'
import { randomPrivkey } from '../helpers'

describe('run_sha256_tests', () => {
    const inputs = [
        '',
        'abc',
        'message digest',
        'secure hash algorithm',
        'SHA256 is considered to be safe',
        'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',
        'For this sample, this 63-byte string will be used as input data',
        'This is exactly 64 bytes long, not counting the terminating byte',
    ]

    const outputs = [
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
        'f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650',
        'f30ceb2bb2829e79e4ca9753d35a8ecc00262d164cc077080295381cbd643f0d',
        '6819d915c73f4d1e77e4e1b52d1fa0f9cf9beaead3939f15874bd988e2a23630',
        '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1',
        'f08a78cbbaee082b052ae0708f32fa1e50c5c421aa772ba5dbb406a2ea6be342',
        'ab64eff7e88e2e46165e29f2bce41826bd4c7b3552f6b382a9e7d3af47c245f8',
    ]

    for (let i = 0; i < inputs.length; i++) {
        const input = inputs[i]
        const output = outputs[i]
        it(`hashes correctly: "${input}"`, () => {
            const actual = u.bufferToHex(hash(u.utf8ToBuffer(input)))
            assert.strictEqual(actual, output)
        })
    }
})

describe('run_hmac_sha256_tests', () => {
    const keys = [
        '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
        '4a656665',
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        '0102030405060708090a0b0c0d0e0f10111213141516171819',
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    ]
    const inputs = [
        '4869205468657265',
        '7768617420646f2079612077616e7420666f72206e6f7468696e673f',
        'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
        'cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd',
        '54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374',
        '5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e',
    ]
    const outputs = [
        'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7',
        '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
        '773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe',
        '82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b',
        '60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54',
        '9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2',
    ]

    for (let i = 0; i < keys.length; i++) {
        const key = u.bufferFromHex(keys[i])
        const input = u.bufferFromHex(inputs[i])
        const output = outputs[i]
        it(`hmacs correctly: "${u.bufferToHex(key)}"`, () => {
            const actual = u.bufferToHex(hmac(key, [input]))
            assert.strictEqual(actual, output)
        })
    }
})

describe('scalar_test', () => {
    it('commutativity of add', () => {
        const s1 = randomPrivkey()
        const s2 = randomPrivkey()
        assert.strictEqual(scalarAdd(s1, s2), scalarAdd(s2, s1))
    })

    it('associativity of add', () => {
        const s = randomPrivkey()
        const s1 = randomPrivkey()
        const s2 = randomPrivkey()
        const r1 = scalarAdd(scalarAdd(s1, s2), s)
        const r2 = scalarAdd(scalarAdd(s2, s), s1)
        assert.strictEqual(r1, r2)
    })

    it('commutativity of multiply', () => {
        const s1 = randomPrivkey()
        const s2 = randomPrivkey()
        assert.strictEqual(scalarMultiply(s1, s2), scalarMultiply(s2, s1))
    })

    it('associativity of multiply', () => {
        const s = randomPrivkey()
        const s1 = randomPrivkey()
        const s2 = randomPrivkey()
        const r1 = scalarMultiply(scalarMultiply(s1, s2), s)
        const r2 = scalarMultiply(scalarMultiply(s2, s), s1)
        assert.strictEqual(r1, r2)
    })

    it('distributitivity of mul over add', () => {
        const s = randomPrivkey()
        const s1 = randomPrivkey()
        const s2 = randomPrivkey()

        let r1 = scalarAdd(s1, s2)
        r1 = scalarMultiply(r1, s)

        let r2 = scalarMultiply(s1, s)
        const t = scalarMultiply(s2, s)
        r2 = scalarAdd(r2, t)

        assert.strictEqual(r1, r2)
    })

    it('multiplicative identity', () => {
        const scalar = randomPrivkey()
        const result = scalarMultiply(scalar, 1n)
        assert.strictEqual(result, scalar)
    })

    it('additive identity', () => {
        const scalar = randomPrivkey()
        const result = scalarAdd(scalar, 0n)
        assert.strictEqual(result, scalar)
    })

    it('zero product property', () => {
        const scalar = randomPrivkey()
        const result = scalarMultiply(scalar, 0n)
        assert.strictEqual(result, 0n)
    })

    it('(-1)+1 should be zero', () => {
        const s = 1n
        const o = scalarNegate(s)

        let result = scalarAdd(o, s)
        assert.strictEqual(result, 0n)

        result = scalarNegate(result)
        assert.strictEqual(result, 0n)
    })

    it('fails on out of bounds scalars', () => {
        assert.throws(() => {
            const hi = Scalar.fromHex(u.bufferToHex(u.bufferFromBigInt(u.curve.n)))
        }, /privkey must be in range 1 to n-1/)
        assert.throws(() => {
            const lo = Scalar.fromHex(u.bufferToHex(u.bufferFromBigInt(0n)))
        }, /privkey must be in range 1 to n-1/)
    })
})

describe('scalar_vectors', () => {
    const chal = [
        [
            'ffff030700000000ffffffffffffff030000000000f8ffffffff0300c0ffffff',
            'ffffffffff0f000000000000000000f8ffffffffffffffffff0300000000e0ff',
        ],
        [
            'efff1f0000000000feffffffffff3f0000000000000000000000000000000000',
            'ffffff000000000000000000000000e0fffffffffcffffffffffffff7f0080ff',
        ],
        [
            'ffffff0000000000000000000006000080000080ff3f0000000000f8ffffff00',
            '0000fcffffffff80ffffffffff0f00e0ffffffffff7f0000000000007fffffff',
        ],
        [
            'ffffff00000000000000000080000080ffffffffffffff00001ef8fffffffdff',
            'ffffffffffffff1f000000f8ff0300e0ff0f00000000f0fff3ff030000000000',
        ],
        [
            '80000080ffffff00001c000000ffffffffffffe0ffffff0000000000e0ffffff',
            'ffffffffffff0300f8ffffffffffffffff1f000080ffff3f00feffffffdfffff',
        ],
        [
            'ffffffff000ffc9fffffff0080000080ff0ffcff7f00000000f8ffffffffff00',
            '08000000000000800000f8ff0fc0ffffff1f000000c0ffffffffff0780ffffff',
        ],
        [
            'ffffffffff3f000080000080fffffffff7ffffefffffff00ffffff00000000f0',
            '00000000f8ffffffffffffff01000000000080ffffffffffffffffffffffffff',
        ],
        [
            '00f8ff03ffffff0000feffffffffff0080000080ffffffffffff03c0ff0ffcff',
            'ffffffffffe0ffffff010000003f00c0ffffffffffffffffffffffffffffffff',
        ],
        [
            '8f0f0000000000000000f8ffffffffffff7f000080000080ffffffffffffff00',
            'ffffffffffffffffff0f00000000000000000000000000000000000000000000',
        ],
        [
            '000000c0ffffffffffffffffffffffffffff030080000080ffffff000080ff7f',
            'ffcfffff0100000000c0ffcfffffffffbfff0e000000000080ffffffff000000',
        ],
        [
            '000000000080ffffffff00fcffffffffffffff0080000080ff01fcff0100feff',
            'ffffff0300000000000000000000000000000000000000c0ffffffffffff0300',
        ],
        [
            'ffffff0000000000e0ffffffffffffff00f8ffffffffffff7f00000080000080',
            '000000000000000000f8ff0100f0ffffe0ff0f00000000000000000000000000',
        ],
        [
            'ffffffffffffffffff0000000000000000000000000000000000000000f8ff00',
            'ffffffffffff0000fcffff3ff0ffff3f0000f807000000ffffffffff0f7e0000',
        ],
        [
            '00ffffffffffff000000000080000080ffffffffffffffffffff1f0000fe0700',
            '000000f0fffffffffffffffffffffffffffbff07000000000000000000000060',
        ],
        [
            'ff0100ffffff0f00807ffeffffffff0300000000000000000080ffffffffffff',
            'ffff1f00f0ffffffffffffffffffffffffffffffffffffffffffff3f00000000',
        ],
        [
            '80000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
            'fffffffffffffffffffffffffffff1ffffffffffffffff03000000e0ffffffff',
        ],
        [
            'ffffffffffffff007e00000000000000c0ffffcfff1f00008000000000000080',
            '00000000000000000000000000e0ffffffffffffff3f007e0000000000000000',
        ],
        [
            '0000000000000000000000fcffffffffffff0300000000000000000000007c00',
            '8000000000000080ffff7f0080000000ffffffffffffff000000e0ffffffffff',
        ],
        [
            'ffffffffff1f0080ffffffffffffff008000000000000080ffffffffffffff00',
            'f0ffffffffffffffffffffff3f000080ff0100000000ffffff7ff8ffff1f00fe',
        ],
        [
            'ffffff3ff8ffffffff03fe0100000000f0ffffffffffffffffffffffffffff07',
            'ffffffffffffff008000000000000080ffffffff0180ffffffffffffffffff00',
        ],
        [
            '0000000000000000000000000000000000000000000000000000000000000000',
            'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140',
        ],
        [
            '0000000000000000000000000000000000000000000000000000000000000001',
            '0000000000000000000000000000000000000000000000000000000000000000',
        ],
        [
            '7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
            '7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
        ],
        [
            'ffffffffff0000c0ff0f0000000000000000f0ffffffffffffffffffffffff7f',
            'ffffffffffff0100f0ffffffff070000000000feffffffffffffffff01ffffff',
        ],
        [
            '7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
            '0000000000000000000000000000000000000000000000000000000000000002',
        ],
        [
            'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140',
            '0000000000000000000000000000000000000000000000000000000000000001',
        ],
        [
            'ffffffffffffffff7e0000c0ffff07008000000080000000fcffffffffffffff',
            'ff01000000e0ffffffffffffff1f0080ffffffffff030000ffffffffffffffff',
        ],
        [
            'fffff0ffffffff00f0ffffffffffff0000e0ffffffffff0180000080ffffffff',
            '0000000000e0ffffffff3f00f8ffffffffffffffffffffffff3f0000c0f17f00',
        ],
        [
            'ffffff0000000000000000c0ffffffffffffff000000000080000080ffffff00',
            '00f8ffffffffff01000000000000f8ffff7f00000000801f0000fcffff01ffff',
        ],
        [
            '00feffffffffff0080000080ff03e001ffffff000000fcffffffffffffffff00',
            'ffffffff00000000fefffff007003c80fffffffffcffffffffff07e0ff000000',
        ],
        [
            'ffffffffffffff00fcffffffffffffffffffffffffff07f80000000080000080',
            'ffffffffffffffffffffffffff0c8000000000c07ffeff1f00feff030000feff',
        ],
        [
            'ffff81ffffffff0080ffffffffffff83ffff000080000080ffff7f00000000f0',
            'ff0100000000f8ffffffffffff1f0000f8070080ffffffffffc7ffffe0ffffff',
        ],
        [
            '82c9fab06804a00082c9fab06804a000ffffffffff6f03fbfa8a7ddf1386e203',
            '82c9fab06804a00082c9fab06804a000ffffffffff6f03fbfa8a7ddf1386e203',
        ],
    ]
    const res = [
        [
            '0c3b0aca8d1a2fb98a7b535a1fc522a1072a48ea02ebb3d6201e86d095f69235',
            'dc907a072e1e446df815245b5a96379c377b0dac1b65584943b731bba7f49715',
        ],
        [
            'f1f73a50e610ba22434d1f1f7c27ca9cb8b6a0fcd8c0052ff708e176ddd080c8',
            'e38080b8dbe3a97700b0f52e27e268c488e804c112bf7859e6a97ce181ddb9d5',
        ],
        [
            '96e2ee01a68031ef5cd019b47d5f79aba197d37e33bb86556020100d942d117c',
            'ccabe0e898651296385a1af28523595ff9f3c281709265129c651e9600efe763',
        ],
        [
            'ac1e62c259fc4e5c83b0d06fce19f6bfa4b0e053661fbfc9334737a93d5db048',
            '86b92a7f8ea86042266d6e1ca2ece0e53e0a33bb614c9f3cd1df4933cd727818',
        ],
        [
            'f7d3cd495c1322fb2eb22f27f58a5d74c158c5c22d9f52c6639fba0576457a63',
            '8afa554ddda3b2c344fdec72deefc099f59fe252b405325857c18feac3245b94',
        ],
        [
            '0583eedd64f0143ba0144a3a41827ca72caab176bb59645f52ad25299d8f0bb0',
            '7ee37ccacd4fb06d7ab23ea008b9a82dc2f49966ccacd8b9722a4a3e0f7bbff4',
        ],
        [
            '8c9c782b39617ef76537660938b96f707887ffcf93ca85064484a7fed3a4e37e',
            'a256492354a550e95ff04de7dc3832794f1cb7e4bbf8bb2e40414bcce31e1636',
        ],
        [
            '0c1ed709254097cb5c46a8daef25d5e5924dcfa3c45d354ae46192f3bf0ecdbe',
            'e4af0ab3308b9b484943c764604a2b9e955f56e835dcebdcc7c4fe3040c7bfa4',
        ],
        [
            'd4a0f581496bb68b0a69f9fea832e5e0a5cd0253f92ce3538336c602b5eb64b8',
            '1d42b9f9e9e3932c4cee6c5a479e62016b04fea4302b0d4f7110d355caf35e80',
        ],
        [
            '7705f60c159b45e7b911b8f5d6da730cda92ead09dd01892ce9aaaee0fefde30',
            'f1f1d69b51d777625210b87a849d154e07dc1e750d0c3bdb7458620290548b43',
        ],
        [
            'a6fe0b8780436725575dec405008d55d43d7e0aae013b6b0c0d4e50d4583d613',
            '40450a9231ea8c608c1fd87645b929002632d8a69688e2c48bdb7f1787ccc8f2',
        ],
        [
            'c256e2b61a81e731632ebb0d2f8167d422e238022597c7886edfbe2aa57363aa',
            '5045e2c3bd89fc57bd3ca3987e7f363892391f0f811a06511f8d6aff4716069c',
        ],
        [
            '3395a26f275f9c9c6445cbd13cee5e5f48a6afe379cfb1e2bf550ea23b62f0e4',
            '14e806e3be7e6701c52167d854b57fa4f975701cfd79db86ad378583564ef0bf',
        ],
        [
            'bca6e0564eeffaf51d5d3f2a5b19ab51c58bdd9828352fc3814f5ce570b9eb62',
            'c46d26b0176bfe6c12f8e7c1f52ffa911327bd73cc33311c39e3276a95cfc5fb',
        ],
        [
            '30b29984f0182a6e1e27eda229994156e8d40def999cf35829551ac068d674a4',
            '079ce7ecf5367341a31ce593976afdf75318abafeb85bd9290ab3cbf3082adf6',
        ],
        [
            'c6878a2aeac0a9ec6dd3dc3223ce6219a47ea8dd1c33aed34f629f52e76546f4',
            '975127672da2828798d3b6147f51d39a0bd07681b24f5892a486a1a7091def9b',
        ],
        [
            'b30f2b690d069064bd434c10e8981ca3e168e9796c29513f41dcdf1ff360be33',
            'a15ff71db43e9b3ce7bdb606d560066d50d2f41a3108f2ea8eef5f7db6d0c027',
        ],
        [
            '629ad9bb3836cef75d2f13ecc82d028a2e72f0e5159d72aefcb34f02eae109fe',
            '00000000fa0a3dbcad160cb6e77c8b399a43bbe3c255151475ac909b7f9a9200',
        ],
        [
            '8bac7086298f00237b4530aab84cc78d4e4785c619e396c29aa012ed6fd77616',
            '45af7e33c77f106c7c9f29c1a87e1584e77dc06dab715dd06b9f97abcb510c9f',
        ],
        [
            '9ec392b4049fc8bbdd9ec605fd65ec947f2c16c440ac637b7db80ce45be3a70e',
            '43f444e8ccc8d454333750f287422e0049606202fd1a7cdb296c6d545308d1c8',
        ],
        [
            '0000000000000000000000000000000000000000000000000000000000000000',
            '0000000000000000000000000000000000000000000000000000000000000000',
        ],
        [
            '0000000000000000000000000000000000000000000000000000000000000000',
            '0000000000000000000000000000000000000000000000000000000000000001',
        ],
        [
            '2759c7356071a6f179a5fd7916f341f057b4029732e7de59e22d9b11ea2c3592',
            '2759c7356071a6f179a5fd7916f341f057b4029732e7de59e22d9b11ea2c3592',
        ],
        [
            '2856ac0e4f9809f049fa7f84ac7e505b174314899c53a89430f2114d921427e8',
            '397a8456799dec262c53c194c98d9e9d321fdd8404e8e20a6bbebb424067306c',
        ],
        [
            '000000000000000000000000000000014551231950b75fc4402da1732fc9bebd',
            '2759c7356071a6f179a5fd7916f341f057b4029732e7de59e22d9b11ea2c3592',
        ],
        [
            'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140',
            '0000000000000000000000000000000000000000000000000000000000000001',
        ],
        [
            '1cc4f7da0f65ca397052928ec3c815ea7f109e774b6e2ddfe8309ddae89a65ae',
            '02b016b11dc8577ba23aa2a3385c8feb663791a85fef04f65975e1ee92f60e30',
        ],
        [
            '8d7614a414069f9adf4a85a76bbf296fbc34875debbb2ea9c91f58d69a82a056',
            'd4b9db881d04e9938d3f20d586a88307db09d8221f7ff171c8e75d47af8b72e9',
        ],
        [
            '83b939b2a4df4687c2b8f1e64cd1e2a9e4703034bc527c55a6ec80a4e5d2dc73',
            '08f103cf1673e87db67e9bc0b4c2a5860277d52786a515fbae9b8ca9f9f8a84a',
        ],
        [
            '8b0049dbfaf01ba2ed8a9a7a36784ac7f7ad39d06c657a41ced6d64c20216bc7',
            'c6ca781d326c6c0691f21ae84316ea043c1f0785f7092208ba13fd781e3f6f62',
        ],
        [
            '259b7cb0ac726fb2e353847a1a9a989b44d359d08e57414078a7302f4c9cb968',
            'b775036361c2486e123dbf4b27dfb17aff4e310783f4625b19a5aca032580da7',
        ],
        [
            '434f10a4cadb3867faae96b56d97ff1fb68343d3a02d707a64054ca7c1a52151',
            'e4f12384e1b59df2b8738b452b354638102b50f88b35cd34c80ef6db0935f0da',
        ],
        [
            'db215c8d831db334c70e43a1587967131e865d8963e60a465c02971b624386f5',
            'db215c8d831db334c70e43a1587967131e865d8963e60a465c02971b624386f5',
        ],
    ]

    // Scalar.fromHex without bounds check.
    function scalarFromHex(hex: string): Scalar {
        return u.bufferToBigInt(u.bufferFromHex(hex))
    }

    it('passes tests.c assertions', () => {
        for (let i = 0; i < chal.length; i++) {
            const [x, y] = chal[i].map(scalarFromHex)
            const [r1, r2] = res[i].map(scalarFromHex)
            let z = scalarMultiply(x, y)
            assert.strictEqual(z, r1)

            if (y !== 0n) {
                let zz = scalarInverse(y)
                z = scalarMultiply(z, zz)
                assert.strictEqual(x, z)

                zz = scalarMultiply(zz, y)
                assert.strictEqual(zz, 1n)
            }

            const xsqr = scalarMultiply(x, x)
            assert.strictEqual(r2, xsqr)
        }
    })
})

describe('test_ecdsa_edge_cases', () => {
    it('verify signature with r of zero fails', () => {
        const pubkey = Point.fromHex('02fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141')
        const sig = { s: 1n, r: 0n }
        const msg = new Uint8Array(32)
        assert.ok(!verify(pubkey, msg, sig))
    })

    it('verify signature with s of zero fails', () => {
        const pubkey = Point.fromHex('020000000000000000000000000000000000000000000000000000000000000001')
        const sig = { s: 0n, r: 1n }
        const msg = new Uint8Array(32)
        assert.ok(!verify(pubkey, msg, sig))
    })

    // https://github.com/ElementsProject/secp256k1-zkp/blob/1bbad3a04be42edb1dda16c9eab24345b1f63c5d/src/tests.c#L4747
    // it('verify signature with message= 0 passes', () => {
    //     const pubkey = Point.fromHex('020000000000000000000000000000000000000000000000000000000000000002')
    //     const pubkey2 = Point.fromHex('02fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364143')
    //     const msg = new Uint8Array(32)
    //     const sig = {
    //         r: 2n,
    //         s: 2n,
    //     }
    //     assert.ok(verify(pubkey, msg, sig))
    //     assert.ok(verify(pubkey2, msg, sig))
    //     sig.s = scalarNegate(sig.s)
    //     assert.ok(verify(pubkey, msg, sig))
    //     assert.ok(verify(pubkey2, msg, sig))
    //     sig.s = 1n
    //     assert.ok(!verify(pubkey, msg, sig))
    //     assert.ok(!verify(pubkey2, msg, sig))
    // })
})
