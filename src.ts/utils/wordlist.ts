
// This gets overriddenby gulp during bip39-XX
const exportWordlist = false;

import { id } from '../utils/hash';

import { defineReadOnly } from '../utils/properties';

export function check(wordlist: Wordlist) {
    const words = [];
    for (let i = 0; i < 2048; i++) {
        const word = wordlist.getWord(i);
        if (i !== wordlist.getWordIndex(word)) { return '0x'; }
        words.push(word);
    }
    return id(words.join('\n') + '\n');
}

export abstract class Wordlist {
    public readonly locale: string;

    constructor(locale: string) {
        defineReadOnly(this, 'locale', locale);
    }

    public abstract getWord(index: number): string;
    public abstract getWordIndex(word: string): number;

    // Subclasses may override this
    public split(mnemonic: string): string[] {
        return mnemonic.toLowerCase().split(/ +/g);
    }

    // Subclasses may override this
    public join(words: string[]): string {
        return words.join(' ');
    }
}

export function register(lang: Wordlist, name?: string): void {
    if (!name) { name = lang.locale; }
    if (exportWordlist) {
        const g: any = (global as any);
        if (!(g.wordlists)) { defineReadOnly(g, 'wordlists', { }); }
        if (!g.wordlists[name]) {
            defineReadOnly(g.wordlists, name, lang);
        }
        if (g.ethers && g.ethers.wordlists) {
            if (!g.ethers.wordlists[name]) {
                defineReadOnly(g.ethers.wordlists, name, lang);
            }
        }
    }
}
