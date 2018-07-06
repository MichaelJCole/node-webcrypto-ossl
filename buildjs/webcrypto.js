import * as crypto from "crypto";
import * as webcrypto from "webcrypto-core";
import { KeyStorage } from "./key_storage";
import * as subtle from "./subtle";
const ERR_RANDOM_VALUE_LENGTH = "Failed to execute 'getRandomValues' on 'Crypto': The ArrayBufferView's byte length (%1) exceeds the number of bytes of entropy available via this API (65536).";
class WebCrypto {
    constructor(options) {
        this.subtle = new subtle.SubtleCrypto();
        if (options && options.directory) {
            this.keyStorage = new KeyStorage(options.directory);
        }
    }
    getRandomValues(array) {
        if (array) {
            if (array.byteLength > 65536) {
                const error = new webcrypto.WebCryptoError(ERR_RANDOM_VALUE_LENGTH, array.byteLength);
                error.code = 22;
                throw error;
            }
            const bytes = crypto.randomBytes(array.byteLength);
            array.set(new array.constructor(bytes.buffer));
            return array;
        }
        return null;
    }
}
module.exports = WebCrypto;
