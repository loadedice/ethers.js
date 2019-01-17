'use strict';

import { ec as EC } from 'elliptic';

import { getAddress } from './address';

import { arrayify, hexlify, hexZeroPad, splitSignature } from './bytes';
import { hashMessage } from './hash';
import { keccak256 } from './keccak256';
import { defineReadOnly } from './properties';

import * as errors from '../errors';

///////////////////////////////
// Imported Types

import { Arrayish, Signature } from './bytes';

///////////////////////////////

let _curve: EC = null;
function getCurve() {
    if (!_curve) {
        _curve = new EC('secp256k1');
    }
    return _curve;
}

export class KeyPair {

    public readonly privateKey: string;

    public readonly publicKey: string;
    public readonly compressedPublicKey: string;

    public readonly publicKeyBytes: Uint8Array;

    constructor(privateKey: Arrayish | string) {
        const keyPair = getCurve().keyFromPrivate(arrayify(privateKey));

        defineReadOnly(this, 'privateKey', hexlify(keyPair.priv.toArray('be', 32)));
        defineReadOnly(this, 'publicKey', '0x' + keyPair.getPublic(false, 'hex'));
        defineReadOnly(this, 'compressedPublicKey', '0x' + keyPair.getPublic(true, 'hex'));
        defineReadOnly(this, 'publicKeyBytes', keyPair.getPublic().encode(null, true));
    }

    public sign(digest: Arrayish | string): Signature {
        const keyPair = getCurve().keyFromPrivate(arrayify(this.privateKey));
        const signature = keyPair.sign(arrayify(digest), {canonical: true});
        return {
            recoveryParam: signature.recoveryParam,
            r: hexZeroPad('0x' + signature.r.toString(16), 32),
            s: hexZeroPad('0x' + signature.s.toString(16), 32),
            v: 27 + signature.recoveryParam,
        };

    }

    public computeSharedSecret(otherKey: Arrayish | string): string {
        const keyPair = getCurve().keyFromPrivate(arrayify(this.privateKey));
        const otherKeyPair = getCurve().keyFromPublic(arrayify(computePublicKey(otherKey)));
        return hexZeroPad('0x' + keyPair.derive(otherKeyPair.getPublic()).toString(16), 32);
    }
}

export function computePublicKey(key: Arrayish | string, compressed?: boolean): string {

    const bytes = arrayify(key);

    if (bytes.length === 32) {
        const keyPair: KeyPair = new KeyPair(bytes);
        if (compressed) {
            return keyPair.compressedPublicKey;
        }
        return keyPair.publicKey;

    } else if (bytes.length === 33) {
        if (compressed) { return hexlify(bytes); }
        return '0x' + getCurve().keyFromPublic(bytes).getPublic(false, 'hex');

    } else if (bytes.length === 65) {
        if (!compressed) { return hexlify(bytes); }
        return '0x' + getCurve().keyFromPublic(bytes).getPublic(true, 'hex');
    }

    errors.throwError('invalid public or private key', errors.INVALID_ARGUMENT, { arg: 'key', value: '[REDACTED]' });
    return null;
}

export function computeAddress(key: Arrayish | string): string {
    // Strip off the leading "0x04"
    const publicKey = '0x' + computePublicKey(key).slice(4);
    return getAddress('0x' + keccak256(publicKey).substring(26));
}

export function recoverPublicKey(digest: Arrayish | string, signature: Signature | string): string {
    const sig = splitSignature(signature);
    const rs = { r: arrayify(sig.r), s: arrayify(sig.s) };
    return '0x' + getCurve().recoverPubKey(arrayify(digest), rs, sig.recoveryParam).encode('hex', false);
}

export function recoverAddress(digest: Arrayish | string, signature: Signature | string): string {
    return computeAddress(recoverPublicKey(arrayify(digest), signature));
}

export function verifyMessage(message: Arrayish | string, signature: Signature | string): string {
    return recoverAddress(hashMessage(message), signature);
}
