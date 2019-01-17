'use strict';

import { getAddress, getContractAddress } from '../utils/address';
import { BigNumber, bigNumberify } from '../utils/bignumber';
import { hexDataLength, hexDataSlice, hexlify, hexStripZeros, isHexString, stripZeros } from '../utils/bytes';
import { namehash } from '../utils/hash';
import { getNetwork } from '../utils/networks';
import { defineReadOnly, inheritable, resolveProperties, shallowCopy } from '../utils/properties';
import { encode as rlpEncode } from '../utils/rlp';
import { parse as parseTransaction } from '../utils/transaction';
import { toUtf8String } from '../utils/utf8';
import { poll } from '../utils/web';

import * as errors from '../errors';

///////////////////////////////
// Imported Abstracts
import { Provider } from './abstract-provider';

///////////////////////////////
// Imported Types

import {
    Block, BlockTag,
    EventType, Filter,
    Listener,
    Log,
    TransactionReceipt, TransactionRequest, TransactionResponse,
} from './abstract-provider';

import { BigNumberish } from '../utils/bignumber';
import { Transaction } from '../utils/transaction';
import { Network, Networkish } from '../utils/networks';

//////////////////////////////
// Request and Response Checking

// @TODO: not any?
function check(format: any, object: any): any {
    const result: any = {};
    for (const key in format) {
        try {
            const value = format[key](object[key]);
            if (value !== undefined) { result[key] = value; }
        } catch (error) {
            error.checkKey = key;
            error.checkValue = object[key];
            throw error;
        }
    }
    return result;
}

type CheckFunc = (value: any) => any;

function allowNull(check: CheckFunc, nullValue?: any): CheckFunc {
    return (function(value: any) {
        if (value == null) { return nullValue; }
        return check(value);
    });
}

function allowFalsish(check: CheckFunc, replaceValue: any): CheckFunc {
    return (function(value) {
        if (!value) { return replaceValue; }
        return check(value);
    });
}

function arrayOf(check: CheckFunc): CheckFunc {
    return (function(array: any): any[] {
        if (!Array.isArray(array)) { throw new Error('not an array'); }

        const result: any = [];

        array.forEach(function(value) {
            result.push(check(value));
        });

        return result;
    });
}

function checkHash(hash: any, requirePrefix?: boolean): string {
    if (typeof(hash) === 'string') {
        // geth-etc does add a "0x" prefix on receipt.root
        if (!requirePrefix && hash.substring(0, 2) !== '0x') { hash = '0x' + hash; }
        if (hexDataLength(hash) === 32) {
           return hash.toLowerCase();
        }
    }
    errors.throwError('invalid hash', errors.INVALID_ARGUMENT, { arg: 'hash', value: hash });
    return null;
}

function checkNumber(number: any): number {
    return bigNumberify(number).toNumber();
}

// Returns the difficulty as a number, or if too large (i.e. PoA network) null
function checkDifficulty(value: BigNumberish): number {
    const v = bigNumberify(value);

    try {
        return v.toNumber();
    } catch (error) { }

    return null;
}

function checkBoolean(value: any): boolean {
    if (typeof(value) === 'boolean') { return value; }
    if (typeof(value) === 'string') {
        if (value === 'true') { return true; }
        if (value === 'false') { return false; }
    }
    throw new Error('invaid boolean - ' + value);
}

function checkUint256(uint256: string): string {
    if (!isHexString(uint256)) {
        throw new Error('invalid uint256');
    }
    while (uint256.length < 66) {
        uint256 = '0x0' + uint256.substring(2);
    }
    return uint256;
}

/*
function checkString(string) {
    if (typeof(string) !== 'string') { throw new Error('invalid string'); }
    return string;
}
*/

function checkBlockTag(blockTag: BlockTag): string {
    if (blockTag == null) { return 'latest'; }

    if (blockTag === 'earliest') { return '0x0'; }

    if (blockTag === 'latest' || blockTag === 'pending') {
        return blockTag;
    }

    if (typeof(blockTag) === 'number') {
        return hexStripZeros(hexlify(blockTag));
    }

    if (isHexString(blockTag)) { return hexStripZeros(blockTag); }

    throw new Error('invalid blockTag');
}

const formatTransaction = {
   hash: checkHash,

   blockHash: allowNull(checkHash, null),
   blockNumber: allowNull(checkNumber, null),
   transactionIndex: allowNull(checkNumber, null),

   confirmations: allowNull(checkNumber, null),

   from: getAddress,

   gasPrice: bigNumberify,
   gasLimit: bigNumberify,
   to: allowNull(getAddress, null),
   value: bigNumberify,
   nonce: checkNumber,
   data: hexlify,

   r: allowNull(checkUint256),
   s: allowNull(checkUint256),
   v: allowNull(checkNumber),

   creates: allowNull(getAddress, null),

   raw: allowNull(hexlify),
};

function checkTransactionResponse(transaction: any): TransactionResponse {

    // Rename gas to gasLimit
    if (transaction.gas != null && transaction.gasLimit == null) {
        transaction.gasLimit = transaction.gas;
    }

    // Some clients (TestRPC) do strange things like return 0x0 for the
    // 0 address; correct this to be a real address
    if (transaction.to && bigNumberify(transaction.to).isZero()) {
        transaction.to = '0x0000000000000000000000000000000000000000';
    }

    // Rename input to data
    if (transaction.input != null && transaction.data == null) {
        transaction.data = transaction.input;
    }

    // If to and creates are empty, populate the creates from the transaction
    if (transaction.to == null && transaction.creates == null) {
        transaction.creates = getContractAddress(transaction);
    }

    // @TODO: use transaction.serialize? Have to add support for including v, r, and s...
    if (!transaction.raw) {

        // Very loose providers (e.g. TestRPC) don't provide a signature or raw
        if (transaction.v && transaction.r && transaction.s) {
            const raw = [
                stripZeros(hexlify(transaction.nonce)),
                stripZeros(hexlify(transaction.gasPrice)),
                stripZeros(hexlify(transaction.gasLimit)),
                (transaction.to || '0x'),
                stripZeros(hexlify(transaction.value || '0x')),
                hexlify(transaction.data || '0x'),
                stripZeros(hexlify(transaction.v || '0x')),
                stripZeros(hexlify(transaction.r)),
                stripZeros(hexlify(transaction.s)),
            ];

            transaction.raw = rlpEncode(raw);
        }
    }

    const result = check(formatTransaction, transaction);

    let networkId = transaction.networkId;

    // geth-etc returns chainId
    if (transaction.chainId != null && networkId == null && result.v == null) {
        networkId = transaction.chainId;
    }

    if (isHexString(networkId)) {
        networkId = bigNumberify(networkId).toNumber();
    }

    if (typeof(networkId) !== 'number' && result.v != null) {
        networkId = (result.v - 35) / 2;
        if (networkId < 0) { networkId = 0; }
        networkId = parseInt(networkId);
    }

    if (typeof(networkId) !== 'number') { networkId = 0; }

    result.networkId = networkId;

    // 0x0000... should actually be null
    if (result.blockHash && result.blockHash.replace(/0/g, '') === 'x') {
        result.blockHash = null;
    }

    return result;
}

const formatBlock = {
    hash: checkHash,
    parentHash: checkHash,
    number: checkNumber,

    timestamp: checkNumber,
    nonce: allowNull(hexlify),
    difficulty: checkDifficulty,

    gasLimit: bigNumberify,
    gasUsed: bigNumberify,

    miner: getAddress,
    extraData: hexlify,

    transactions: allowNull(arrayOf(checkHash)),
};

const formatBlockWithTransactions = shallowCopy(formatBlock);
formatBlockWithTransactions.transactions = allowNull(arrayOf(checkTransactionResponse));

function checkBlock(block: any, includeTransactions: boolean): Block {
    if (block.author != null && block.miner == null) {
        block.miner = block.author;
    }
    return check(includeTransactions ? formatBlockWithTransactions : formatBlock, block);
}

const formatTransactionRequest = {
    from: allowNull(getAddress),
    nonce: allowNull(checkNumber),
    gasLimit: allowNull(bigNumberify),
    gasPrice: allowNull(bigNumberify),
    to: allowNull(getAddress),
    value: allowNull(bigNumberify),
    data: allowNull(hexlify),
};

function checkTransactionRequest(transaction: any): any {
    return check(formatTransactionRequest, transaction);
}

const formatTransactionReceiptLog = {
    transactionLogIndex: allowNull(checkNumber),
    transactionIndex: checkNumber,
    blockNumber: checkNumber,
    transactionHash: checkHash,
    address: getAddress,
    topics: arrayOf(checkHash),
    data: hexlify,
    logIndex: checkNumber,
    blockHash: checkHash,
};

function checkTransactionReceiptLog(log: any): any {
    return check(formatTransactionReceiptLog, log);
}

const formatTransactionReceipt = {
    contractAddress: allowNull(getAddress, null),
    transactionIndex: checkNumber,
    root: allowNull(checkHash),
    gasUsed: bigNumberify,
    logsBloom: allowNull(hexlify),
    blockHash: checkHash,
    transactionHash: checkHash,
    logs: arrayOf(checkTransactionReceiptLog),
    blockNumber: checkNumber,
    confirmations: allowNull(checkNumber, null),
    cumulativeGasUsed: bigNumberify,
    status: allowNull(checkNumber),
};

function checkTransactionReceipt(transactionReceipt: any): TransactionReceipt {
    // var status = transactionReceipt.status;
    // var root = transactionReceipt.root;

    const result: TransactionReceipt = check(formatTransactionReceipt, transactionReceipt);
    result.logs.forEach(function(entry, index) {
        if (entry.transactionLogIndex == null) {
            entry.transactionLogIndex = index;
        }
    });
    if (transactionReceipt.status != null) {
        result.byzantium = true;
    }
    return result;
}

function checkTopics(topics: any): any {
    if (Array.isArray(topics)) {
        topics.forEach(function(topic) {
            checkTopics(topic);
        });

    } else if (topics != null) {
        checkHash(topics);
    }

    return topics;
}

const formatFilter = {
    fromBlock: allowNull(checkBlockTag, undefined),
    toBlock: allowNull(checkBlockTag, undefined),
    address: allowNull(getAddress, undefined),
    topics: allowNull(checkTopics, undefined),
};

function checkFilter(filter: any): any {
    return check(formatFilter, filter);
}

const formatLog = {
    blockNumber: allowNull(checkNumber),
    blockHash: allowNull(checkHash),
    transactionIndex: checkNumber,

    removed: allowNull(checkBoolean),

    address: getAddress,
    data: allowFalsish(hexlify, '0x'),

    topics: arrayOf(checkHash),

    transactionHash: checkHash,
    logIndex: checkNumber,
};

function checkLog(log: any): any {
    return check(formatLog, log);
}

//////////////////////////////
// Event Serializeing

function serializeTopics(topics: Array<string | string[]>): string {
    return topics.map((topic) => {
        if (typeof(topic) === 'string') {
            return topic;
        } else if (Array.isArray(topic)) {
            topic.forEach((topic) => {
                if (topic !== null && hexDataLength(topic) !== 32) {
                    errors.throwError('invalid topic', errors.INVALID_ARGUMENT, { argument: 'topic', value: topic });
                }
            });
            return topic.join(',');
        } else if (topic === null) {
            return '';
        }
        return errors.throwError('invalid topic value', errors.INVALID_ARGUMENT, { argument: 'topic', value: topic });
    }).join('&');
}

function deserializeTopics(data: string): Array<string | string[]> {
    return data.split(/&/g).map((topic) => {
        const comps = topic.split(',');
        if (comps.length === 1) {
            if (comps[0] === '') { return null; }
            return topic;
        }

        return comps.map((topic) => {
            if (topic === '') { return null; }
            return topic;
        });
    });
}

function getEventTag(eventName: EventType): string {
    if (typeof(eventName) === 'string') {
        if (hexDataLength(eventName) === 20) {
            return 'address:' + getAddress(eventName);
        }

        eventName = eventName.toLowerCase();

        if (hexDataLength(eventName) === 32) {
            return 'tx:' + eventName;
        }

        if (eventName.indexOf(':') === -1) {
            return eventName;
        }

    } else if (Array.isArray(eventName)) {
        return 'filter::' + serializeTopics(eventName);

    } else if (eventName && typeof(eventName) === 'object') {
        return 'filter:' + (eventName.address || '') + ':' + serializeTopics(eventName.topics || []);
    }

    throw new Error('invalid event - ' + eventName);
}

//////////////////////////////
// Helper Object

function getTime() {
    return (new Date()).getTime();
}

//////////////////////////////
// Provider Object

/**
 *  EventType
 *   - "block"
 *   - "pending"
 *   - "error"
 *   - address
 *   - filter
 *   - topics array
 *   - transaction hash
 */

interface _Event {
    listener: Listener;
    once: boolean;
    tag: string;
}

export class BaseProvider extends Provider {

    get network(): Network {
        return this._network;
    }

    get blockNumber(): number {
        return this._fastBlockNumber;
    }

    get polling(): boolean {
        return (this._poller != null);
    }

    set polling(value: boolean) {
        setTimeout(() => {
            if (value && !this._poller) {
                this._poller = setInterval(this._doPoll.bind(this), this.pollingInterval);

            } else if (!value && this._poller) {
                clearInterval(this._poller);
                this._poller = null;
            }
        }, 0);
    }

    get pollingInterval(): number {
        return this._pollingInterval;
    }

    set pollingInterval(value: number) {
        if (typeof(value) !== 'number' || value <= 0 || parseInt(String(value)) != value) {
            throw new Error('invalid polling interval');
        }

        this._pollingInterval = value;

        if (this._poller) {
            clearInterval(this._poller);
            this._poller = setInterval(() => { this._doPoll(); }, this._pollingInterval);
        }
    }

    public static checkTransactionResponse(transaction: any): TransactionResponse {
        return checkTransactionResponse(transaction);
    }

    // To help mitigate the eventually conssitent nature of the blockchain
    // we keep a mapping of events we emit. If we emit an event X, we expect
    // that a user should be able to query for that event in the callback,
    // if the node returns null, we stall the response until we get back a
    // meaningful value, since we may be hitting a re-org, or a node that
    // has not indexed the event yet.
    // Events:
    //   - t:{hash}    - Transaction hash
    //   - b:{hash}    - BlockHash
    //   - block       - The most recent emitted block
    protected _emitted: { [ eventName: string ]: number | 'pending' };

    /**
     *  ready
     *
     *  A Promise<Network> that resolves only once the provider is ready.
     *
     *  Sub-classes that call the super with a network without a chainId
     *  MUST set this. Standard named networks have a known chainId.
     *
     */
    protected ready: Promise<Network>;
    private _network: Network;

    private _events: _Event[];

    private _pollingInterval: number;
    private _poller: any; // @TODO: what does TypeScript think setInterval returns?

    private _lastBlockNumber: number;

    // string => BigNumber
    private _balances: any;

    private _fastBlockNumber: number;
    private _fastBlockNumberPromise: Promise<number>;
    private _fastQueryDate: number;

    constructor(network: Networkish | Promise<Network>) {
        super();
        errors.checkNew(this, Provider);

        if (network instanceof Promise) {
            defineReadOnly(this, 'ready', network.then((network) => {
                defineReadOnly(this, '_network', network);
                return network;
            }));

            // Squash any "unhandled promise" errors; the don't need to be handled
            this.ready.catch((error) => { });

        } else {
            const knownNetwork = getNetwork((network == null) ? 'homestead' : network);
            if (knownNetwork) {
                defineReadOnly(this, '_network', knownNetwork);
                defineReadOnly(this, 'ready', Promise.resolve(this._network));

            } else {
                errors.throwError('invalid network', errors.INVALID_ARGUMENT, { arg: 'network', value: network });
            }
        }

        this._lastBlockNumber = -2;

        // Balances being watched for changes
        this._balances = {};

        // Events being listened to
        this._events = [];

        this._pollingInterval = 4000;

        this._emitted = { block: -2 };

        this._fastQueryDate = 0;
    }

    public resetEventsBlock(blockNumber: number): void {
        this._lastBlockNumber = blockNumber - 1;
        if (this.polling) { this._doPoll(); }
    }

    public getNetwork(): Promise<Network> {
        return this.ready;
    }

    public _getFastBlockNumber(): Promise<number> {
        const now = getTime();

        // Stale block number, request a newer value
        if ((now - this._fastQueryDate) > 2 * this._pollingInterval) {
            this._fastQueryDate = now;
            this._fastBlockNumberPromise = this.getBlockNumber().then((blockNumber) => {
                if (this._fastBlockNumber == null || blockNumber > this._fastBlockNumber) {
                    this._fastBlockNumber = blockNumber;
                }
                return this._fastBlockNumber;
            });
        }

        return this._fastBlockNumberPromise;
    }

    public _setFastBlockNumber(blockNumber: number): void {
        // Older block, maybe a stale request
        if (this._fastBlockNumber != null && blockNumber < this._fastBlockNumber) { return; }

        // Update the time we updated the blocknumber
        this._fastQueryDate = getTime();

        // Newer block number, use  it
        if (this._fastBlockNumber == null || blockNumber > this._fastBlockNumber) {
            this._fastBlockNumber = blockNumber;
            this._fastBlockNumberPromise = Promise.resolve(blockNumber);
        }
    }

    // @TODO: Add .poller which must be an event emitter with a 'start', 'stop' and 'block' event;
    //        this will be used once we move to the WebSocket or other alternatives to polling

    public waitForTransaction(transactionHash: string, confirmations?: number): Promise<TransactionReceipt> {
        if (confirmations == null) { confirmations = 1; }
        return poll(() => {
            return this.getTransactionReceipt(transactionHash).then((receipt) => {
                if (confirmations === 0) { return receipt; }
                if (receipt == null || receipt.confirmations < confirmations) {
                    return undefined;
                }
                return receipt;
            });
        }, { onceBlock: this });
    }

    public getBlockNumber(): Promise<number> {
        return this.ready.then(() => {
            return this.perform('getBlockNumber', { }).then((result) => {
                const value = parseInt(result);
                if (value != result) { throw new Error('invalid response - getBlockNumber'); }
                this._setFastBlockNumber(value);
                return value;
            });
        });
    }

    public getGasPrice(): Promise<BigNumber> {
        return this.ready.then(() => {
            return this.perform('getGasPrice', { }).then((result) => {
                return bigNumberify(result);
            });
        });
    }

    public getBalance(addressOrName: string | Promise<string>, blockTag?: BlockTag | Promise<BlockTag>): Promise<BigNumber> {
        return this.ready.then(() => {
            return resolveProperties({ addressOrName, blockTag }).then(({ addressOrName, blockTag }) => {
                return this.resolveName(addressOrName).then((address) => {
                    const params = { address, blockTag: checkBlockTag(blockTag) };
                    return this.perform('getBalance', params).then((result) => {
                        return bigNumberify(result);
                    });
                });
            });
        });
    }

    public getTransactionCount(addressOrName: string | Promise<string>, blockTag?: BlockTag | Promise<BlockTag>): Promise<number> {
        return this.ready.then(() => {
            return resolveProperties({ addressOrName, blockTag }).then(({ addressOrName, blockTag }) => {
                return this.resolveName(addressOrName).then((address) => {
                    const params = { address, blockTag: checkBlockTag(blockTag) };
                    return this.perform('getTransactionCount', params).then((result) => {
                        return bigNumberify(result).toNumber();
                    });
                });
            });
        });
    }

    public getCode(addressOrName: string | Promise<string>, blockTag?: BlockTag | Promise<BlockTag>): Promise<string> {
        return this.ready.then(() => {
            return resolveProperties({ addressOrName, blockTag }).then(({ addressOrName, blockTag }) => {
                return this.resolveName(addressOrName).then((address) => {
                    const params = {address, blockTag: checkBlockTag(blockTag)};
                    return this.perform('getCode', params).then((result) => {
                        return hexlify(result);
                    });
                });
            });
        });
    }

    public getStorageAt(addressOrName: string | Promise<string>, position: BigNumberish | Promise<BigNumberish>, blockTag?: BlockTag | Promise<BlockTag>): Promise<string> {
        return this.ready.then(() => {
            return resolveProperties({ addressOrName, position, blockTag }).then(({ addressOrName, position, blockTag }) => {
                return this.resolveName(addressOrName).then((address) => {
                    const params = {
                        address,
                        blockTag: checkBlockTag(blockTag),
                        position: hexStripZeros(hexlify(position)),
                    };
                    return this.perform('getStorageAt', params).then((result) => {
                        return hexlify(result);
                    });
                });
            });
        });
    }

    public sendTransaction(signedTransaction: string | Promise<string>): Promise<TransactionResponse> {
        return this.ready.then(() => {
            return resolveProperties({ signedTransaction }).then(({ signedTransaction }) => {
                const params = { signedTransaction: hexlify(signedTransaction) };
                return this.perform('sendTransaction', params).then((hash) => {
                    return this._wrapTransaction(parseTransaction(signedTransaction), hash);
                }, function(error) {
                    error.transaction = parseTransaction(signedTransaction);
                    if (error.transaction.hash) {
                        (error as any).transactionHash = error.transaction.hash;
                    }
                    throw error;
                });
            });
        });
    }

    // This should be called by any subclass wrapping a TransactionResponse
    public _wrapTransaction(tx: Transaction, hash?: string): TransactionResponse {
        if (hash != null && hexDataLength(hash) !== 32) { throw new Error('invalid response - sendTransaction'); }

        const result: TransactionResponse = tx as TransactionResponse;

        // Check the hash we expect is the same as the hash the server reported
        if (hash != null && tx.hash !== hash) {
            errors.throwError('Transaction hash mismatch from Provider.sendTransaction.', errors.UNKNOWN_ERROR, { expectedHash: tx.hash, returnedHash: hash });
        }

        // @TODO: (confirmations? number, timeout? number)
        result.wait = (confirmations?: number) => {

            // We know this transaction *must* exist (whether it gets mined is
            // another story), so setting an emitted value forces us to
            // wait even if the node returns null for the receipt
            if (confirmations !== 0) {
                this._emitted['t:' + tx.hash] = 'pending';
            }

            return this.waitForTransaction(tx.hash, confirmations).then((receipt) => {
                if (receipt == null && confirmations === 0) { return null; }

                // No longer pending, allow the polling loop to garbage collect this
                this._emitted['t:' + tx.hash] = receipt.blockNumber;

                if (receipt.status === 0) {
                    errors.throwError('transaction failed', errors.CALL_EXCEPTION, {
                        transactionHash: tx.hash,
                        transaction: tx,
                    });
                }
                return receipt;
            });
        };

        return result;
    }

    public call(transaction: TransactionRequest, blockTag?: BlockTag | Promise<BlockTag>): Promise<string> {
        const tx: TransactionRequest = shallowCopy(transaction);
        return this.ready.then(() => {
            return resolveProperties({ blockTag, tx }).then(({ blockTag, tx }) => {
                return this._resolveNames(tx, [ 'to', 'from' ]).then((tx) => {
                    const params = { blockTag: checkBlockTag(blockTag), transaction: checkTransactionRequest(tx) };
                    return this.perform('call', params).then((result) => {
                        return hexlify(result);
                    });
                });
            });
        });
    }

    public estimateGas(transaction: TransactionRequest) {
        const tx: TransactionRequest = {
            to: transaction.to,
            from: transaction.from,
            data: transaction.data,
            gasPrice: transaction.gasPrice,
            value: transaction.value,
        };

        return this.ready.then(() => {
            return resolveProperties(tx).then((tx) => {
                return this._resolveNames(tx, [ 'to', 'from' ]).then((tx) => {
                    const params = { transaction: checkTransactionRequest(tx) };
                    return this.perform('estimateGas', params).then((result) => {
                        return bigNumberify(result);
                    });
                });
            });
        });
   }

    public getBlock(blockHashOrBlockTag: BlockTag | string | Promise<BlockTag | string>, includeTransactions?: boolean): Promise<Block> {
        return this.ready.then(() => {
            return resolveProperties({ blockHashOrBlockTag }).then(({ blockHashOrBlockTag }) => {
                try {
                    const blockHash = hexlify(blockHashOrBlockTag);
                    if (hexDataLength(blockHash) === 32) {
                        return poll(() => {
                            return this.perform('getBlock', { blockHash, includeTransactions: !!includeTransactions }).then((block) => {
                                if (block == null) {
                                    if (this._emitted['b:' + blockHash] == null) {
                                        return null;
                                    }
                                    return undefined;
                                }
                                return checkBlock(block, includeTransactions);
                            });
                        }, { onceBlock: this });

                    }
                } catch (error) { }

                try {
                    let blockNumber = -128;

                    const blockTag = checkBlockTag(blockHashOrBlockTag);
                    if (isHexString(blockTag)) {
                        blockNumber = parseInt(blockTag.substring(2), 16);
                    }

                    return poll(() => {
                        return this.perform('getBlock', { blockTag, includeTransactions: !!includeTransactions }).then((block) => {
                            if (block == null) {
                                if (blockNumber <= this._emitted.block) {
                                    return undefined;
                                }
                                return null;
                            }
                            return checkBlock(block, includeTransactions);
                        });
                    }, { onceBlock: this });
                } catch (error) { }

                throw new Error('invalid block hash or block tag');
            });
        });
    }

    public getTransaction(transactionHash: string): Promise<TransactionResponse> {
        return this.ready.then(() => {
            return resolveProperties({ transactionHash }).then(({ transactionHash }) => {
                const params = { transactionHash: checkHash(transactionHash, true) };
                return poll(() => {
                    return this.perform('getTransaction', params).then((result) => {
                        if (result == null) {
                            if (this._emitted['t:' + transactionHash] == null) {
                                return null;
                            }
                            return undefined;
                        }

                        const tx = BaseProvider.checkTransactionResponse(result);

                        if (tx.blockNumber == null) {
                            tx.confirmations = 0;

                        } else if (tx.confirmations == null) {
                            return this._getFastBlockNumber().then((blockNumber) => {

                                // Add the confirmations using the fast block number (pessimistic)
                                let confirmations = (blockNumber - tx.blockNumber) + 1;
                                if (confirmations <= 0) { confirmations = 1; }
                                tx.confirmations = confirmations;

                                return this._wrapTransaction(tx);
                            });
                        }

                        return this._wrapTransaction(tx);
                    });
                }, { onceBlock: this });
            });
        });
    }

    public getTransactionReceipt(transactionHash: string): Promise<TransactionReceipt> {
        return this.ready.then(() => {
            return resolveProperties({ transactionHash }).then(({ transactionHash }) => {
                const params = { transactionHash: checkHash(transactionHash, true) };
                return poll(() => {
                    return this.perform('getTransactionReceipt', params).then((result) => {
                        if (result == null) {
                            if (this._emitted['t:' + transactionHash] == null) {
                                return null;
                            }
                            return undefined;
                        }

                        // "geth-etc" returns receipts before they are ready
                        if (result.blockHash == null) { return undefined; }

                        const receipt = checkTransactionReceipt(result);

                        if (receipt.blockNumber == null) {
                            receipt.confirmations = 0;

                        } else if (receipt.confirmations == null) {
                            return this._getFastBlockNumber().then((blockNumber) => {

                                // Add the confirmations using the fast block number (pessimistic)
                                let confirmations = (blockNumber - receipt.blockNumber) + 1;
                                if (confirmations <= 0) { confirmations = 1; }
                                receipt.confirmations = confirmations;

                                return receipt;
                            });
                        }

                        return receipt;
                    });
                }, { onceBlock: this });
            });
        });
    }

    public getLogs(filter: Filter): Promise<Log[]> {
        return this.ready.then(() => {
            return resolveProperties(filter).then((filter) => {
                return this._resolveNames(filter, ['address']).then((filter) => {
                    const params = { filter: checkFilter(filter) };
                    return this.perform('getLogs', params).then((result) => {
                        return arrayOf(checkLog)(result);
                    });
                });
            });
        });
    }

    public getEtherPrice(): Promise<number> {
        return this.ready.then(() => {
            return this.perform('getEtherPrice', {}).then((result) => {
                // @TODO: Check valid float
                return result;
            });
        });
    }

    public resolveName(name: string | Promise<string>): Promise<string> {

        // If it is a promise, resolve it then recurse
        if (name instanceof Promise) {
            return name.then((addressOrName) => {
                return this.resolveName(addressOrName);
            });
        }

        // If it is already an address, nothing to resolve
        try {
            return Promise.resolve(getAddress(name));
        } catch (error) { }

        const self = this;

        const nodeHash = namehash(name);

        // Get the addr from the resovler
        return this._getResolver(name).then(function(resolverAddress) {

            // keccak256('addr(bytes32)')
            const data = '0x3b3b57de' + nodeHash.substring(2);
            const transaction = { to: resolverAddress, data };
            return self.call(transaction);

        // extract the address from the data
        }).then(function(data) {
            if (hexDataLength(data) !== 32) { return null; }
            const address = getAddress(hexDataSlice(data, 12));
            if (address === '0x0000000000000000000000000000000000000000') { return null; }
            return address;
        });
    }

    public lookupAddress(address: string | Promise<string>): Promise<string> {
        if (address instanceof Promise) {
            return address.then((address) => {
                return this.lookupAddress(address);
            });
        }

        address = getAddress(address);

        const name = address.substring(2) + '.addr.reverse';
        const nodehash = namehash(name);

        const self = this;

        return this._getResolver(name).then(function(resolverAddress) {
            if (!resolverAddress) { return null; }

            // keccak('name(bytes32)')
            const data = '0x691f3431' + nodehash.substring(2);
            const transaction = { to: resolverAddress, data };
            return self.call(transaction);

        }).then(function(data) {
            // Strip off the "0x"
            data = data.substring(2);

            // Strip off the dynamic string pointer (0x20)
            if (data.length < 64) { return null; }
            data = data.substring(64);

            if (data.length < 64) { return null; }
            const length = bigNumberify('0x' + data.substring(0, 64)).toNumber();
            data = data.substring(64);

            if (2 * length > data.length) { return null; }

            const name = toUtf8String('0x' + data.substring(0, 2 * length));

            // Make sure the reverse record matches the foward record
            return self.resolveName(name).then(function(addr) {
                if (addr != address) { return null; }
                return name;
            });

        });
    }

    public doPoll(): void {
    }

    public perform(method: string, params: any): Promise<any> {
        errors.throwError(method + ' not implemented', errors.NOT_IMPLEMENTED, { operation: method });
        return null;
    }

    public on(eventName: EventType, listener: Listener): Provider {
        this._addEventListener(eventName, listener, false);
        return this;
    }

    public once(eventName: EventType, listener: Listener): Provider {
        this._addEventListener(eventName, listener, true);
        return this;
    }

    public addEventListener(eventName: EventType, listener: Listener): Provider {
        return this.on(eventName, listener);
    }

    public emit(eventName: EventType, ...args: any[]): boolean {
        let result = false;

        const eventTag = getEventTag(eventName);
        this._events = this._events.filter((event) => {
            if (event.tag !== eventTag) { return true; }
            setTimeout(() => {
                event.listener.apply(this, args);
            }, 0);
            result = true;
            return !(event.once);
        });

        if (this.listenerCount() === 0) { this.polling = false; }

        return result;
    }

    public listenerCount(eventName?: EventType): number {
        if (!eventName) { return this._events.length; }

        const eventTag = getEventTag(eventName);
        return this._events.filter((event) => {
            return (event.tag === eventTag);
        }).length;
    }

    public listeners(eventName: EventType): Listener[] {
        const eventTag = getEventTag(eventName);
        return this._events.filter((event) => {
            return (event.tag === eventTag);
        }).map((event) => {
            return event.listener;
        });
    }

    public removeAllListeners(eventName: EventType): Provider {
        const eventTag = getEventTag(eventName);
        this._events = this._events.filter((event) => {
            return (event.tag !== eventTag);
        });

        if (eventName === 'pending') { this._stopPending(); }
        if (this._events.length === 0) { this.polling = false; }

        return this;
    }

    public removeListener(eventName: EventType, listener: Listener): Provider {
        let found = false;

        const eventTag = getEventTag(eventName);
        this._events = this._events.filter((event) => {
            if (event.tag !== eventTag) { return true; }
            if (found) { return true; }
            found = false;
            return false;
        });

        if (eventName === 'pending' && this.listenerCount('pending') === 0) { this._stopPending(); }
        if (this.listenerCount() === 0) { this.polling = false; }

        return this;
    }

    protected _startPending(): void {
        errors.warn('WARNING: this provider does not support pending events');
    }

    protected _stopPending(): void {
    }

    private _doPoll(): void {
        this.getBlockNumber().then((blockNumber) => {
            this._setFastBlockNumber(blockNumber);

            // If the block hasn't changed, meh.
            if (blockNumber === this._lastBlockNumber) { return; }

            // First polling cycle, trigger a "block" events
            if (this._emitted.block === -2) {
                this._emitted.block = blockNumber - 1;
            }

            // Notify all listener for each block that has passed
            for (let i = (this._emitted.block as number) + 1; i <= blockNumber; i++) {
                this.emit('block', i);
            }

            // The emitted block was updated, check for obsolete events
            if ((this._emitted.block as number) !== blockNumber) {
                this._emitted.block = blockNumber;

                Object.keys(this._emitted).forEach((key) => {
                    // The block event does not expire
                    if (key === 'block') { return; }

                    // The block we were at when we emitted this event
                    const eventBlockNumber = this._emitted[key];

                    // We cannot garbage collect pending transactions or blocks here
                    // They should be garbage collected by the Provider when setting
                    // "pending" events
                    if (eventBlockNumber === 'pending') { return; }

                    // Evict any transaction hashes or block hashes over 12 blocks
                    // old, since they should not return null anyways
                    if (blockNumber - eventBlockNumber > 12) {
                        delete this._emitted[key];
                    }
                });
            }

            // First polling cycle
            if (this._lastBlockNumber === -2) {
                this._lastBlockNumber = blockNumber - 1;
            }

            // Sweep balances and remove addresses we no longer have events for
            const newBalances: any = {};

            // Find all transaction hashes we are waiting on
            this._events.forEach((event) => {
                const comps = event.tag.split(':');
                switch (comps[0]) {
                    case 'tx': {
                        const hash = comps[1];
                        this.getTransactionReceipt(hash).then((receipt) => {
                            if (!receipt || receipt.blockNumber == null) { return null; }
                            this._emitted['t:' + hash] = receipt.blockNumber;
                            this.emit(hash, receipt);
                            return null;
                        }).catch((error: Error) => { this.emit('error', error); });

                        break;
                    }

                    case 'address': {
                        const address = comps[1];
                        if (this._balances[address]) {
                            newBalances[address] = this._balances[address];
                        }

                        this.getBalance(address, 'latest').then((balance) => {
                            const lastBalance = this._balances[address];
                            if (lastBalance && balance.eq(lastBalance)) { return; }
                            this._balances[address] = balance;
                            this.emit(address, balance);
                            return null;
                        }).catch((error: Error) => { this.emit('error', error); });

                        break;
                    }

                    case 'filter': {
                        const topics = deserializeTopics(comps[2]);
                        const filter = {
                            address: comps[1],
                            fromBlock: this._lastBlockNumber + 1,
                            toBlock: blockNumber,
                            topics,
                        };
                        if (!filter.address) { delete filter.address; }
                        this.getLogs(filter).then((logs) => {
                            if (logs.length === 0) { return; }
                            logs.forEach((log: Log) => {
                                this._emitted['b:' + log.blockHash] = log.blockNumber;
                                this._emitted['t:' + log.transactionHash] = log.blockNumber;
                                this.emit(filter, log);
                            });
                            return null;
                        }).catch((error: Error) => { this.emit('error', error); });
                        break;
                    }
                }
            });

            this._lastBlockNumber = blockNumber;

            this._balances = newBalances;

            return null;
        }).catch((error: Error) => { });

        this.doPoll();
    }

    // @TODO: Could probably use resolveProperties instead?
    private _resolveNames(object: any, keys: string[]): Promise<{ [key: string]: string }> {
        const promises: Array<Promise<void>> = [];

        const result: { [key: string ]: string } = shallowCopy(object);

        keys.forEach(function(key) {
            if (result[key] == null) { return; }
            promises.push(this.resolveName(result[key]).then((address: string) => {
                result[key] = address;
                return;
            }));
        }, this);

        return Promise.all(promises).then(function() { return result; });
    }

    private _getResolver(name: string): Promise<string> {
        // Get the resolver from the blockchain
        return this.getNetwork().then((network) => {

            // No ENS...
            if (!network.ensAddress) {
                errors.throwError(
                    'network does support ENS',
                    errors.UNSUPPORTED_OPERATION,
                    { operation: 'ENS', network: network.name },
                );
            }

            // keccak256('resolver(bytes32)')
            const data = '0x0178b8bf' + namehash(name).substring(2);
            const transaction = { to: network.ensAddress, data };

            return this.call(transaction).then((data) => {

                // extract the address from the data
                if (hexDataLength(data) !== 32) { return null; }
                return getAddress(hexDataSlice(data, 12));
            });
        });
    }

    private _addEventListener(eventName: EventType, listener: Listener, once: boolean): void {
        this._events.push({
            tag: getEventTag(eventName),
            listener,
            once,
        });
        if (eventName === 'pending') { this._startPending(); }
        this.polling = true;
    }

}

defineReadOnly(Provider, 'inherits', inheritable(Provider));
