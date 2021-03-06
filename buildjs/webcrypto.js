"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var crypto = require("crypto");
var webcrypto = require("webcrypto-core");
var key_storage_1 = require("./key_storage");
var subtle = require("./subtle");
var ERR_RANDOM_VALUE_LENGTH = "Failed to execute 'getRandomValues' on 'Crypto': The ArrayBufferView's byte length (%1) exceeds the number of bytes of entropy available via this API (65536).";
var WebCrypto = (function () {
    function WebCrypto(options) {
        this.subtle = new subtle.SubtleCrypto();
        if (options && options.directory) {
            this.keyStorage = new key_storage_1.KeyStorage(options.directory);
        }
    }
    WebCrypto.prototype.getRandomValues = function (array) {
        if (array) {
            if (array.byteLength > 65536) {
                var error = new webcrypto.WebCryptoError(ERR_RANDOM_VALUE_LENGTH, array.byteLength);
                error.code = 22;
                throw error;
            }
            var bytes = crypto.randomBytes(array.byteLength);
            array.set(new array.constructor(bytes.buffer));
            return array;
        }
        return null;
    };
    return WebCrypto;
}());
module.exports = WebCrypto;
