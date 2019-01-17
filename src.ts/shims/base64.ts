'use strict';

import { arrayify } from '../utils/bytes';

module.exports = {
    decode(textData: string): Uint8Array {
         textData = atob(textData);
         let data = [];
         for (let i = 0; i < textData.length; i++) {
             data.push(textData.charCodeAt(i));
         }
         return arrayify(data);
    },
    encode(data: Uint8Array): string {
        data = arrayify(data);
        let textData = '';
        for (let i = 0; i < data.length; i++) {
            textData += String.fromCharCode(data[i]);
        }
        return btoa(textData);
    },
};
