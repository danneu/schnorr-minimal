import { mod, powmod, secp256k1 as curve } from './util'

export interface Point {
    readonly x: bigint
    readonly y: bigint
}

export function add(a: Point, b: Point): Point {
    if (a === INFINITE_POINT) {
        return b
    }
    if (b === INFINITE_POINT) {
        return a
    }
    if (a.x === b.x && a.y !== b.y) {
        return INFINITE_POINT
    }
    const lam =
        a.x === b.x && a.y === b.y
            ? ((3n * a.x * a.x + curve.a) * powmod(2n * a.y, curve.p - 2n, curve.p)) % curve.p
            : ((b.y - a.y) * powmod(b.x - a.x, curve.p - 2n, curve.p)) % curve.p
    const x3 = (lam * lam - a.x - b.x) % curve.p
    const y = mod(lam * (a.x - x3) - a.y, curve.p)
    return { x: x3, y }
}

export function multiply(point: Point, scalar: bigint): Point {
    scalar = scalar % curve.n
    let r = INFINITE_POINT
    for (let i = 0n; i < 256n; i++) {
        if ((scalar >> i) & 1n) {
            r = add(r, point)
        }
        point = add(point, point)
    }
    return r
}

export const INFINITE_POINT: Point = new class {
    get x(): bigint {
        throw new Error("infinite point doesn't have an x")
    }

    get y(): bigint {
        throw new Error("infinite point doesn't have a y")
    }
}()
