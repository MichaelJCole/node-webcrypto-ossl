import { AlgorithmError, AlgorithmNames, Base64Url, BaseCrypto, WebCryptoError } from "webcrypto-core";
import { CryptoKey } from "../key";
import * as native from "../native";
function b64_decode(b64url) {
    return new Buffer(Base64Url.decode(b64url));
}
export class AesCrypto extends BaseCrypto {
    static generateKey(algorithm, extractable, keyUsages) {
        return new Promise((resolve, reject) => {
            native.AesKey.generate(algorithm.length / 8, (err, key) => {
                if (err) {
                    reject(err);
                }
                else {
                    const aes = new CryptoKey(key, algorithm, "secret", extractable, keyUsages);
                    resolve(aes);
                }
            });
        });
    }
    static importKey(format, keyData, algorithm, extractable, keyUsages) {
        return new Promise((resolve, reject) => {
            const formatLC = format.toLocaleLowerCase();
            let raw;
            switch (formatLC) {
                case "jwk":
                    raw = b64_decode(keyData.k);
                    break;
                case "raw":
                    raw = keyData;
                    break;
                default:
                    throw new WebCryptoError(`ImportKey: Wrong format value '${format}'`);
            }
            algorithm.length = raw.byteLength * 8;
            native.AesKey.import(raw, (err, key) => {
                if (err) {
                    reject(err);
                }
                else {
                    resolve(new CryptoKey(key, algorithm, "secret", extractable, keyUsages));
                }
            });
        });
    }
    static exportKey(format, key) {
        return new Promise((resolve, reject) => {
            const nativeKey = key.native;
            switch (format.toLocaleLowerCase()) {
                case "jwk":
                    const jwk = {
                        kty: "oct",
                        alg: "",
                        key_ops: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
                        k: "",
                        ext: true,
                    };
                    jwk.alg = "A" + key.algorithm.length + /-(\w+)$/.exec(key.algorithm.name)[1].toUpperCase();
                    nativeKey.export((err, data) => {
                        if (err) {
                            reject(err);
                        }
                        else {
                            jwk.k = Base64Url.encode(data);
                            resolve(jwk);
                        }
                    });
                    break;
                case "raw":
                    nativeKey.export((err, data) => {
                        if (err) {
                            reject(err);
                        }
                        else {
                            resolve(data.buffer);
                        }
                    });
                    break;
                default: throw new WebCryptoError(`ExportKey: Unknown export format '${format}'`);
            }
        });
    }
    static encrypt(algorithm, key, data) {
        if (algorithm.name.toUpperCase() === AlgorithmNames.AesKW) {
            return this.WrapUnwrap(key.native, data, true);
        }
        else {
            return this.EncryptDecrypt(algorithm, key, data, true);
        }
    }
    static decrypt(algorithm, key, data) {
        if (algorithm.name.toUpperCase() === AlgorithmNames.AesKW) {
            return this.WrapUnwrap(key.native, data, false);
        }
        else {
            return this.EncryptDecrypt(algorithm, key, data, false);
        }
    }
    static EncryptDecrypt(algorithm, key, data, type) {
        return new Promise((resolve, reject) => {
            const nativeKey = key.native;
            switch (algorithm.name.toLowerCase()) {
                case AlgorithmNames.AesGCM.toLowerCase(): {
                    const algGCM = algorithm;
                    const iv = new Buffer(algorithm.iv);
                    const aad = algGCM.additionalData ? new Buffer(algGCM.additionalData) : new Buffer(0);
                    const tagLength = algGCM.tagLength || 128;
                    if (type) {
                        nativeKey.encryptGcm(iv, data, aad || new Buffer(0), tagLength / 8, (err, data2) => {
                            if (err) {
                                reject(err);
                            }
                            else {
                                resolve(data2.buffer);
                            }
                        });
                    }
                    else {
                        nativeKey.decryptGcm(iv, data, aad || new Buffer(0), tagLength / 8, (err, data2) => {
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
                case AlgorithmNames.AesCBC.toLowerCase(): {
                    const algCBC = "CBC";
                    const iv = new Buffer(algorithm.iv);
                    if (type) {
                        nativeKey.encrypt(algCBC, iv, data, (err, data2) => {
                            if (err) {
                                reject(err);
                            }
                            else {
                                resolve(data2.buffer);
                            }
                        });
                    }
                    else {
                        nativeKey.decrypt(algCBC, iv, data, (err, data2) => {
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
                case AlgorithmNames.AesCTR.toLowerCase(): {
                    const alg = algorithm;
                    const counter = new Buffer(alg.counter);
                    if (type) {
                        nativeKey.encryptCtr(data, counter, alg.length, (err, data2) => {
                            if (err) {
                                reject(err);
                            }
                            else {
                                resolve(data2.buffer);
                            }
                        });
                    }
                    else {
                        nativeKey.decryptCtr(data, counter, alg.length, (err, data2) => {
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
                case AlgorithmNames.AesECB.toLowerCase(): {
                    if (type) {
                        nativeKey.encryptEcb(data, (err, data2) => {
                            if (err) {
                                reject(err);
                            }
                            else {
                                resolve(data2.buffer);
                            }
                        });
                    }
                    else {
                        nativeKey.decryptEcb(data, (err, data2) => {
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
                default: throw new AlgorithmError(AlgorithmError.NOT_SUPPORTED, algorithm.name);
            }
        });
    }
    static WrapUnwrap(key, data, enc) {
        return new Promise((resolve, reject) => {
            const fn = enc ? key.wrapKey : key.unwrapKey;
            fn.call(key, data, (err, data2) => {
                if (err) {
                    reject(err);
                }
                else {
                    resolve(new Uint8Array(data2).buffer);
                }
            });
        });
    }
}
