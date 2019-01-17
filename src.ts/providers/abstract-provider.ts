
import { BigNumber } from '../utils/bignumber';
import { isType, setType } from '../utils/properties';

///////////////////////////////
// Imported Types

import { Arrayish } from '../utils/bytes';
import { BigNumberish } from '../utils/bignumber';
import { Network } from '../utils/networks';
import { OnceBlockable } from '../utils/web';
import { Transaction } from '../utils/transaction';

///////////////////////////////
// Exported Types

export interface Block {
    hash: string;
    parentHash: string;
    number: number;

    timestamp: number;
    nonce: string;
    difficulty: number;

    gasLimit: BigNumber;
    gasUsed: BigNumber;

    miner: string;
    extraData: string;

    transactions: string[];
}

export type BlockTag = string | number;

export interface Filter {
    fromBlock?: BlockTag;
    toBlock?: BlockTag;
    address?: string;
    topics?: Array<string | string[]>;
}

export interface Log {
    blockNumber?: number;
    blockHash?: string;
    transactionIndex?: number;

    removed?: boolean;

    transactionLogIndex?: number;

    address: string;
    data: string;

    topics: string[];

    transactionHash?: string;
    logIndex?: number;
}

export interface TransactionReceipt {
    contractAddress?: string;
    transactionIndex?: number;
    root?: string;
    gasUsed?: BigNumber;
    logsBloom?: string;
    blockHash?: string;
    transactionHash?: string;
    logs?: Log[];
    blockNumber?: number;
    confirmations?: number;
    cumulativeGasUsed?: BigNumber;
    byzantium: boolean;
    status?: number;
}

export interface TransactionRequest {
    to?: string | Promise<string>;
    from?: string | Promise<string>;
    nonce?: BigNumberish | Promise<BigNumberish>;

    gasLimit?: BigNumberish | Promise<BigNumberish>;
    gasPrice?: BigNumberish | Promise<BigNumberish>;

    data?: Arrayish | Promise<Arrayish>;
    value?: BigNumberish | Promise<BigNumberish>;
    chainId?: number | Promise<number>;
}

export interface TransactionResponse extends Transaction {
    // Only if a transaction has been mined
    blockNumber?: number;
    blockHash?: string;
    timestamp?: number;

    confirmations: number;

    // Not optional (as it is in Transaction)
    from: string;

    // The raw transaction
    raw?: string;

    // This function waits until the transaction has been mined
    wait: (confirmations?: number) => Promise<TransactionReceipt>;
}

export type EventType = string | string[] | Filter;

export type Listener = (...args: any[]) => void;

///////////////////////////////
// Exported Abstracts

export abstract class Provider implements OnceBlockable {

    public static isProvider(value: any): value is Provider {
        return isType(value, 'Provider');
    }

    constructor() {
        setType(this, 'Provider');
    }
    public abstract getNetwork(): Promise<Network>;

    public abstract getBlockNumber(): Promise<number>;
    public abstract getGasPrice(): Promise<BigNumber>;

    public abstract getBalance(addressOrName: string | Promise<string>, blockTag?: BlockTag | Promise<BlockTag>): Promise<BigNumber>;
    public abstract getTransactionCount(addressOrName: string | Promise<string>, blockTag?: BlockTag | Promise<BlockTag>): Promise<number>;
    public abstract getCode(addressOrName: string | Promise<string>, blockTag?: BlockTag | Promise<BlockTag>): Promise<string> ;
    public abstract getStorageAt(addressOrName: string | Promise<string>, position: BigNumberish | Promise<BigNumberish>, blockTag?: BlockTag | Promise<BlockTag>): Promise<string>;

    public abstract sendTransaction(signedTransaction: string | Promise<string>): Promise<TransactionResponse>;
    public abstract call(transaction: TransactionRequest, blockTag?: BlockTag | Promise<BlockTag>): Promise<string>;
    public abstract estimateGas(transaction: TransactionRequest): Promise<BigNumber>;

    public abstract getBlock(blockHashOrBlockTag: BlockTag | string | Promise<BlockTag | string>, includeTransactions?: boolean): Promise<Block>;
    public abstract getTransaction(transactionHash: string): Promise<TransactionResponse>;
    public abstract getTransactionReceipt(transactionHash: string): Promise<TransactionReceipt>;

    public abstract getLogs(filter: Filter): Promise<Log[]>;

    public abstract resolveName(name: string | Promise<string>): Promise<string>;
    public abstract lookupAddress(address: string | Promise<string>): Promise<string>;
    public abstract on(eventName: EventType, listener: Listener): Provider;
    public abstract once(eventName: EventType, listener: Listener): Provider;
    public abstract listenerCount(eventName?: EventType): number;
    public abstract listeners(eventName: EventType): Listener[];
    public abstract removeAllListeners(eventName: EventType): Provider;
    public abstract removeListener(eventName: EventType, listener: Listener): Provider;

    // @TODO: This *could* be implemented here, but would pull in events...
    public abstract waitForTransaction(transactionHash: string, timeout?: number): Promise<TransactionReceipt>;

//    readonly inherits: (child: any) => void;
}

// defineReadOnly(Signer, 'inherits', inheritable(Abstract));
