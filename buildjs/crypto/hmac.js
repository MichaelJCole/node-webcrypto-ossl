import * as webcrypto from "webcrypto-core";
const AlgorithmError = webcrypto.AlgorithmError;
const WebCryptoError = webcrypto.WebCryptoError;
const AlgorithmNames = webcrypto.AlgorithmNames;
const BaseCrypto = webcrypto.BaseCrypto;
const Base64Url = webcrypto.Base64Url;
import { CryptoKey } from "../key";
import * as native from "../native";
function b64_decode(b64url) {
    return new Buffer(Base64Url.decode(b64url));
}
export class HmacCrypto extends BaseCrypto {
    static generateKey(algorithm, extractable, keyUsages) {
        return new Promise((resolve, reject) => {
            const length = algorithm.length || this.getHashSize(algorithm.hash.name);
            native.HmacKey.generate(length, (err, key) => {
                if (err) {
                    reject(err);
                }
                else {
                    resolve(new CryptoKey(key, algorithm, "secret", extractable, keyUsages));
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
            native.HmacKey.import(raw, (err, key) => {
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
                        key_ops: ["sign", "verify"],
                        k: "",
                        ext: true,
                    };
                    jwk.alg = "HS" + /-(\d+)$/.exec(key.algorithm.hash.name)[1];
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
    static sign(algorithm, key, data) {
        return new Promise((resolve, reject) => {
            const alg = this.wc2ssl(key.algorithm);
            const nativeKey = key.native;
            nativeKey.sign(alg, data, (err, signature) => {
                if (err) {
                    reject(new WebCryptoError("NativeError: " + err.message));
                }
                else {
                    resolve(signature.buffer);
                }
            });
        });
    }
    static verify(algorithm, key, signature, data) {
        return new Promise((resolve, reject) => {
            const alg = this.wc2ssl(key.algorithm);
            const nativeKey = key.native;
            nativeKey.verify(alg, data, signature, (err, res) => {
                if (err) {
                    reject(new WebCryptoError("NativeError: " + err.message));
                }
                else {
                    resolve(res);
                }
            });
        });
    }
    static wc2ssl(algorithm) {
        const alg = algorithm.hash.name.toUpperCase().replace("-", "");
        return alg;
    }
    static getHashSize(hashName) {
        switch (hashName) {
            case AlgorithmNames.Sha1:
                return 160;
            case AlgorithmNames.Sha256:
                return 256;
            case AlgorithmNames.Sha384:
                return 384;
            case AlgorithmNames.Sha512:
                return 512;
            default:
                throw new AlgorithmError(AlgorithmError.NOT_SUPPORTED, hashName);
        }
    }
}
