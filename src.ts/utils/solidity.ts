'use strict';

import { bigNumberify } from './bignumber';
import { arrayify, concat, hexlify, padZeros} from './bytes';
import { toUtf8Bytes } from './utf8';

import { keccak256 as hashKeccak256 } from './keccak256';
import { sha256 as hashSha256 } from './sha2';

const regexBytes = new RegExp('^bytes([0-9]+)$');
const regexNumber = new RegExp('^(u?int)([0-9]*)$');
const regexArray = new RegExp('^(.*)\\[([0-9]*)\\]$');

const Zeros = '0000000000000000000000000000000000000000000000000000000000000000';

function _pack(type: string, value: any, isArray?: boolean): Uint8Array {
    switch (type) {
        case 'address':
            if (isArray) { return padZeros(value, 32); }
            return arrayify(value);
        case 'string':
            return toUtf8Bytes(value);
        case 'bytes':
            return arrayify(value);
        case 'bool':
            value = (value ? '0x01' : '0x00');
            if (isArray) { return padZeros(value, 32); }
            return arrayify(value);
    }

    let match =  type.match(regexNumber);
    if (match) {
        // var signed = (match[1] === 'int')
        let size = parseInt(match[2] || '256');
        if ((size % 8 != 0) || size === 0 || size > 256) {
            throw new Error('invalid number type - ' + type);
        }

        if (isArray) { size = 256; }

        value = bigNumberify(value).toTwos(size);

        return padZeros(value, size / 8);
    }

    match = type.match(regexBytes);
    if (match) {
        const size = parseInt(match[1]);
        if (String(size) != match[1] || size === 0 || size > 32) {
            throw new Error('invalid number type - ' + type);
        }
        if (arrayify(value).byteLength !== size) { throw new Error('invalid value for ' + type); }
        if (isArray) { return arrayify((value + Zeros).substring(0, 66)); }
        return value;
    }

    match = type.match(regexArray);
    if (match && Array.isArray(value)) {
        const baseType = match[1];
        const count = parseInt(match[2] || String(value.length));
        if (count != value.length) { throw new Error('invalid value for ' + type); }
        const result: Uint8Array[] = [];
        value.forEach(function(value) {
            result.push(_pack(baseType, value, true));
        });
        return concat(result);
    }

    throw new Error('unknown type - ' + type);
}

// @TODO: Array Enum

export function pack(types: string[], values: any[]) {
    if (types.length != values.length) { throw new Error('type/value count mismatch'); }
    const tight: Uint8Array[] = [];
    types.forEach(function(type, index) {
        tight.push(_pack(type, values[index]));
    });
    return hexlify(concat(tight));
}

export function keccak256(types: string[], values: any[]) {
    return hashKeccak256(pack(types, values));
}

export function sha256(types: string[], values: any[]) {
    return hashSha256(pack(types, values));
}
