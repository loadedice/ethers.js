
import { isType, setType } from './utils/properties';

// Imported Abstracts
import { Provider } from './providers/abstract-provider';

// Imported Types
import { Arrayish } from './utils/bytes';
import { TransactionRequest, TransactionResponse } from './providers/abstract-provider';

export abstract class Signer {

    public static isSigner(value: any): value is Signer {
        return isType(value, 'Signer');
    }
    public readonly provider?: Provider;

    constructor() {
        setType(this, 'Signer');
    }

    public abstract getAddress(): Promise<string>;

    public abstract signMessage(message: Arrayish | string): Promise<string>;
    public abstract sendTransaction(transaction: TransactionRequest): Promise<TransactionResponse>;

//    readonly inherits: (child: any) => void;
}

// defineReadOnly(Signer, 'inherits', inheritable(Signer));
