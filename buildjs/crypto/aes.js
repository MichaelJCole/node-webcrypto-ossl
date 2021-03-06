"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var tslib_1 = require("tslib");
var webcrypto_core_1 = require("webcrypto-core");
var key_1 = require("../key");
var native = require("../native");
function b64_decode(b64url) {
    return new Buffer(webcrypto_core_1.Base64Url.decode(b64url));
}
var AesCrypto = (function (_super) {
    tslib_1.__extends(AesCrypto, _super);
    function AesCrypto() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    AesCrypto.generateKey = function (algorithm, extractable, keyUsages) {
        return new Promise(function (resolve, reject) {
            native.AesKey.generate(algorithm.length / 8, function (err, key) {
                if (err) {
                    reject(err);
                }
                else {
                    var aes = new key_1.CryptoKey(key, algorithm, "secret", extractable, keyUsages);
                    resolve(aes);
                }
            });
        });
    };
    AesCrypto.importKey = function (format, keyData, algorithm, extractable, keyUsages) {
        return new Promise(function (resolve, reject) {
            var formatLC = format.toLocaleLowerCase();
            var raw;
            switch (formatLC) {
                case "jwk":
                    raw = b64_decode(keyData.k);
                    break;
                case "raw":
                    raw = keyData;
                    break;
                default:
                    throw new webcrypto_core_1.WebCryptoError("ImportKey: Wrong format value '" + format + "'");
            }
            algorithm.length = raw.byteLength * 8;
            native.AesKey.import(raw, function (err, key) {
                if (err) {
                    reject(err);
                }
                else {
                    resolve(new key_1.CryptoKey(key, algorithm, "secret", extractable, keyUsages));
                }
            });
        });
    };
    AesCrypto.exportKey = function (format, key) {
        return new Promise(function (resolve, reject) {
            var nativeKey = key.native;
            switch (format.toLocaleLowerCase()) {
                case "jwk":
                    var jwk_1 = {
                        kty: "oct",
                        alg: "",
                        key_ops: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
                        k: "",
                        ext: true,
                    };
                    jwk_1.alg = "A" + key.algorithm.length + /-(\w+)$/.exec(key.algorithm.name)[1].toUpperCase();
                    nativeKey.export(function (err, data) {
                        if (err) {
                            reject(err);
                        }
                        else {
                            jwk_1.k = webcrypto_core_1.Base64Url.encode(data);
                            resolve(jwk_1);
                        }
                    });
                    break;
                case "raw":
                    nativeKey.export(function (err, data) {
                        if (err) {
                            reject(err);
                        }
                        else {
                            resolve(data.buffer);
                        }
                    });
                    break;
                default: throw new webcrypto_core_1.WebCryptoError("ExportKey: Unknown export format '" + format + "'");
            }
        });
    };
    AesCrypto.encrypt = function (algorithm, key, data) {
        if (algorithm.name.toUpperCase() === webcrypto_core_1.AlgorithmNames.AesKW) {
            return this.WrapUnwrap(key.native, data, true);
        }
        else {
            return this.EncryptDecrypt(algorithm, key, data, true);
        }
    };
    AesCrypto.decrypt = function (algorithm, key, data) {
        if (algorithm.name.toUpperCase() === webcrypto_core_1.AlgorithmNames.AesKW) {
            return this.WrapUnwrap(key.native, data, false);
        }
        else {
            return this.EncryptDecrypt(algorithm, key, data, false);
        }
    };
    AesCrypto.EncryptDecrypt = function (algorithm, key, data, type) {
        return new Promise(function (resolve, reject) {
            var nativeKey = key.native;
            switch (algorithm.name.toLowerCase()) {
                case webcrypto_core_1.AlgorithmNames.AesGCM.toLowerCase(): {
                    var algGCM = algorithm;
                    var iv = new Buffer(algorithm.iv);
                    var aad = algGCM.additionalData ? new Buffer(algGCM.additionalData) : new Buffer(0);
                    var tagLength = algGCM.tagLength || 128;
                    if (type) {
                        nativeKey.encryptGcm(iv, data, aad || new Buffer(0), tagLength / 8, function (err, data2) {
                            if (err) {
                                reject(err);
                            }
                            else {
                                resolve(data2.buffer);
                            }
                        });
                    }
                    else {
                        nativeKey.decryptGcm(iv, data, aad || new Buffer(0), tagLength / 8, function (err, data2) {
                            if (err) {
                                reject(err);
                            }
                            else {
                                resolve(data2.buffer);
                            }
                        });
                    }
                    break;
                }
                case webcrypto_core_1.AlgorithmNames.AesCBC.toLowerCase(): {
                    var algCBC = "CBC";
                    var iv = new Buffer(algorithm.iv);
                    if (type) {
                        nativeKey.encrypt(algCBC, iv, data, function (err, data2) {
                            if (err) {
                                reject(err);
                            }
                            else {
                                resolve(data2.buffer);
                            }
                        });
                    }
                    else {
                        nativeKey.decrypt(algCBC, iv, data, function (err, data2) {
                            if (err) {
                                reject(err);
                            }
                            else {
                                resolve(data2.buffer);
                            }
                        });
                    }
                    break;
                }
                case webcrypto_core_1.AlgorithmNames.AesCTR.toLowerCase(): {
                    var alg = algorithm;
                    var counter = new Buffer(alg.counter);
                    if (type) {
                        nativeKey.encryptCtr(data, counter, alg.length, function (err, data2) {
                            if (err) {
                                reject(err);
                            }
                            else {
                                resolve(data2.buffer);
                            }
                        });
                    }
                    else {
                        nativeKey.decryptCtr(data, counter, alg.length, function (err, data2) {
                            if (err) {
                                reject(err);
                            }
                            else {
                                resolve(data2.buffer);
                            }
                        });
                    }
                    break;
                }
                case webcrypto_core_1.AlgorithmNames.AesECB.toLowerCase(): {
                    if (type) {
                        nativeKey.encryptEcb(data, function (err, data2) {
                            if (err) {
                                reject(err);
                            }
                            else {
                                resolve(data2.buffer);
                            }
                        });
                    }
                    else {
                        nativeKey.decryptEcb(data, function (err, data2) {
                            if (err) {
                                reject(err);
                            }
                            else {
                                resolve(data2.buffer);
                            }
                        });
                    }
                    break;
                }
                default: throw new webcrypto_core_1.AlgorithmError(webcrypto_core_1.AlgorithmError.NOT_SUPPORTED, algorithm.name);
            }
        });
    };
    AesCrypto.WrapUnwrap = function (key, data, enc) {
        return new Promise(function (resolve, reject) {
            var fn = enc ? key.wrapKey : key.unwrapKey;
            fn.call(key, data, function (err, data2) {
                if (err) {
                    reject(err);
                }
                else {
                    resolve(new Uint8Array(data2).buffer);
                }
            });
        });
    };
    return AesCrypto;
}(webcrypto_core_1.BaseCrypto));
exports.AesCrypto = AesCrypto;
