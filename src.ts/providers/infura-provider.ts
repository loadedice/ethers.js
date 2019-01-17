'use strict';

import { JsonRpcProvider, JsonRpcSigner } from './json-rpc-provider';

import { getNetwork } from '../utils/networks';
import { defineReadOnly } from '../utils/properties';

// Imported Types
import { Networkish } from '../utils/networks';

import * as errors from '../errors';

export class InfuraProvider extends JsonRpcProvider {
    public readonly apiAccessToken: string;

    constructor(network?: Networkish, apiAccessToken?: string) {
        network = getNetwork((network == null) ? 'homestead' : network);

        let host = null;
        switch (network.name) {
            case 'homestead':
                host = 'mainnet.infura.io';
                break;
            case 'ropsten':
                host = 'ropsten.infura.io';
                break;
            case 'rinkeby':
                host = 'rinkeby.infura.io';
                break;
            case 'kovan':
                host = 'kovan.infura.io';
                break;
            default:
                throw new Error('unsupported network');
        }

        super('https://' + host + '/' + (apiAccessToken || ''), network);
        errors.checkNew(this, InfuraProvider);

        defineReadOnly(this, 'apiAccessToken', apiAccessToken || null);
    }

    public getSigner(address?: string): JsonRpcSigner {
        errors.throwError(
            'INFURA does not support signing',
            errors.UNSUPPORTED_OPERATION,
            { operation: 'getSigner' },
        );
        return null;
    }

    public listAccounts(): Promise<string[]> {
        return Promise.resolve([]);
    }

    protected _startPending(): void {
        errors.warn('WARNING: INFURA does not support pending filters');
    }
}
