import * as webcrypto from "webcrypto-core";
const AlgorithmError = webcrypto.AlgorithmError;
const WebCryptoError = webcrypto.WebCryptoError;
const AlgorithmNames = webcrypto.AlgorithmNames;
const BaseCrypto = webcrypto.BaseCrypto;
const Base64Url = webcrypto.Base64Url;
import { CryptoKey } from "../key";
import * as native from "../native";
import * as aes from "./aes";
function nc2ssl(nc) {
    let namedCurve = "";
    switch (nc.toUpperCase()) {
        case "P-192":
            namedCurve = "secp192r1";
            break;
        case "P-256":
            namedCurve = "secp256r1";
            break;
        case "P-384":
            namedCurve = "secp384r1";
            break;
        case "P-521":
            namedCurve = "secp521r1";
            break;
        case "K-256":
            namedCurve = "secp256k1";
            break;
        default:
            throw new WebCryptoError("Unsupported namedCurve in use");
    }
    return native.EcNamedCurves[namedCurve];
}
function b64_decode(b64url) {
    return new Buffer(Base64Url.decode(b64url));
}
function buf_pad(buf, padSize) {
    padSize = padSize || 0;
    if (padSize && Buffer.length < padSize) {
        const pad = new Buffer(new Uint8Array(padSize - buf.length).map((v) => 0));
        return Buffer.concat([pad, buf]);
    }
    return buf;
}
export class EcCrypto extends BaseCrypto {
    static generateKey(algorithm, extractable, keyUsages) {
        return new Promise((resolve, reject) => {
            const alg = algorithm;
            const namedCurve = nc2ssl(alg.namedCurve);
            native.Key.generateEc(namedCurve, (err, key) => {
                if (err) {
                    reject(err);
                }
                else {
                    const prvUsages = ["sign", "deriveKey", "deriveBits"]
                        .filter((usage) => keyUsages.some((keyUsage) => keyUsage === usage));
                    const pubUsages = ["verify"]
                        .filter((usage) => keyUsages.some((keyUsage) => keyUsage === usage));
                    resolve({
                        privateKey: new CryptoKey(key, algorithm, "private", extractable, prvUsages),
                        publicKey: new CryptoKey(key, algorithm, "public", true, pubUsages),
                    });
                }
            });
        });
    }
    static importKey(format, keyData, algorithm, extractable, keyUsages) {
        return new Promise((resolve, reject) => {
            const formatLC = format.toLocaleLowerCase();
            const alg = algorithm;
            const data = {};
            let keyType = native.KeyType.PUBLIC;
            switch (formatLC) {
                case "raw":
                    if (!Buffer.isBuffer(keyData)) {
                        throw new WebCryptoError("ImportKey: keyData is not a Buffer");
                    }
                    if (!alg.namedCurve) {
                        throw new WebCryptoError("ImportKey: namedCurve property of algorithm parameter is required");
                    }
                    let keyLength = 0;
                    if (keyData.length === 65) {
                        keyLength = 32;
                    }
                    else if (keyData.length === 97) {
                        keyLength = 48;
                    }
                    else if (keyData.length === 133) {
                        keyLength = 66;
                    }
                    const x = keyData.slice(1, keyLength + 1);
                    const y = keyData.slice(keyLength + 1, (keyLength * 2) + 1);
                    data["kty"] = new Buffer("EC", "utf-8");
                    data["crv"] = nc2ssl(alg.namedCurve.toUpperCase());
                    data["x"] = b64_decode(Base64Url.encode(buf_pad(x, keyLength)));
                    data["y"] = b64_decode(Base64Url.encode(buf_pad(y, keyLength)));
                    native.Key.importJwk(data, keyType, (err, key) => {
                        try {
                            if (err) {
                                reject(new WebCryptoError(`ImportKey: Cannot import key from JWK\n${err}`));
                            }
                            else {
                                const ec = new CryptoKey(key, alg, keyType ? "private" : "public", extractable, keyUsages);
                                resolve(ec);
                            }
                        }
                        catch (e) {
                            reject(e);
                        }
                    });
                    break;
                case "jwk":
                    const jwk = keyData;
                    data["kty"] = jwk.kty;
                    data["crv"] = nc2ssl(jwk.crv);
                    data["x"] = b64_decode(jwk.x);
                    data["y"] = b64_decode(jwk.y);
                    if (jwk.d) {
                        keyType = native.KeyType.PRIVATE;
                        data["d"] = b64_decode(jwk.d);
                    }
                    native.Key.importJwk(data, keyType, (err, key) => {
                        try {
                            if (err) {
                                reject(new WebCryptoError(`ImportKey: Cannot import key from JWK\n${err}`));
                            }
                            else {
                                const ec = new CryptoKey(key, alg, keyType ? "private" : "public", extractable, keyUsages);
                                resolve(ec);
                            }
                        }
                        catch (e) {
                            reject(e);
                        }
                    });
                    break;
                case "pkcs8":
                case "spki":
                    if (!Buffer.isBuffer(keyData)) {
                        throw new WebCryptoError("ImportKey: keyData is not a Buffer");
                    }
                    let importFunction = native.Key.importPkcs8;
                    if (formatLC === "spki") {
                        importFunction = native.Key.importSpki;
                    }
                    importFunction(keyData, (err, key) => {
                        try {
                            if (err) {
                                reject(new WebCryptoError(`ImportKey: Can not import key for ${format}\n${err.message}`));
                            }
                            else {
                                const ec = new CryptoKey(key, alg, format.toLocaleLowerCase() === "spki" ? "public" : "private", extractable, keyUsages);
                                resolve(ec);
                            }
                        }
                        catch (e) {
                            reject(e);
                        }
                    });
                    break;
                default:
                    throw new WebCryptoError(`ImportKey: Wrong format value '${format}'`);
            }
        });
    }
    static exportKey(format, key) {
        return new Promise((resolve, reject) => {
            const nativeKey = key.native;
            const type = key.type === "public" ? native.KeyType.PUBLIC : native.KeyType.PRIVATE;
            switch (format.toLocaleLowerCase()) {
                case "jwk":
                    nativeKey.exportJwk(type, (err, data) => {
                        try {
                            const jwk = { kty: "EC" };
                            jwk.crv = key.algorithm.namedCurve;
                            jwk.key_ops = key.usages;
                            let padSize = 0;
                            switch (jwk.crv) {
                                case "P-256":
                                case "K-256":
                                    padSize = 32;
                                    break;
                                case "P-384":
                                    padSize = 48;
                                    break;
                                case "P-521":
                                    padSize = 66;
                                    break;
                                default:
                                    throw new Error(`Unsupported named curve '${jwk.crv}'`);
                            }
                            jwk.x = Base64Url.encode(buf_pad(data.x, padSize));
                            jwk.y = Base64Url.encode(buf_pad(data.y, padSize));
                            if (key.type === "private") {
                                jwk.d = Base64Url.encode(buf_pad(data.d, padSize));
                            }
                            resolve(jwk);
                        }
                        catch (e) {
                            reject(e);
                        }
                    });
                    break;
                case "spki":
                    nativeKey.exportSpki((err, raw) => {
                        if (err) {
                            reject(err);
                        }
                        else {
                            resolve(raw.buffer);
                        }
                    });
                    break;
                case "pkcs8":
                    nativeKey.exportPkcs8((err, raw) => {
                        if (err) {
                            reject(err);
                        }
                        else {
                            resolve(raw.buffer);
                        }
                    });
                    break;
                case "raw":
                    nativeKey.exportJwk(type, (err, data) => {
                        if (err) {
                            reject(err);
                        }
                        else {
                            let padSize = 0;
                            const crv = key.algorithm.namedCurve;
                            switch (crv) {
                                case "P-256":
                                case "K-256":
                                    padSize = 32;
                                    break;
                                case "P-384":
                                    padSize = 48;
                                    break;
                                case "P-521":
                                    padSize = 66;
                                    break;
                                default:
                                    throw new Error(`Unsupported named curve '${crv}'`);
                            }
                            const x = Base64Url.decode(Base64Url.encode(buf_pad(data.x, padSize)));
                            const y = Base64Url.decode(Base64Url.encode(buf_pad(data.y, padSize)));
                            const rawKey = new Uint8Array(1 + x.length + y.length);
                            rawKey.set([4]);
                            rawKey.set(x, 1);
                            rawKey.set(y, 1 + x.length);
                            resolve(rawKey.buffer);
                        }
                    });
                    break;
                default:
                    throw new WebCryptoError(`ExportKey: Unknown export format '${format}'`);
            }
        });
    }
    static sign(algorithm, key, data) {
        return new Promise((resolve, reject) => {
            const alg = this.wc2ssl(algorithm);
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
            const alg = this.wc2ssl(algorithm);
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
    static deriveKey(algorithm, baseKey, derivedKeyType, extractable, keyUsages) {
        return new Promise((resolve, reject) => {
            const algDerivedKeyType = derivedKeyType;
            const alg = algorithm;
            let AesClass;
            switch (algDerivedKeyType.name.toLowerCase()) {
                case AlgorithmNames.AesCBC.toLowerCase():
                case AlgorithmNames.AesGCM.toLowerCase():
                case AlgorithmNames.AesKW.toLowerCase():
                    AesClass = aes.AesCrypto;
                    break;
                default:
                    throw new AlgorithmError(AlgorithmError.NOT_SUPPORTED, algDerivedKeyType.name);
            }
            baseKey.native.EcdhDeriveKey(alg.public.native, algDerivedKeyType.length / 8, (err, raw) => {
                if (err) {
                    reject(err);
                }
                else {
                    AesClass.importKey("raw", raw, algDerivedKeyType, extractable, keyUsages)
                        .then(resolve, reject);
                }
            });
        });
    }
    static deriveBits(algorithm, baseKey, length) {
        return new Promise((resolve, reject) => {
            const alg = algorithm;
            const nativeKey = baseKey.native;
            nativeKey.EcdhDeriveBits(alg.public.native, length, (err, raw) => {
                if (err) {
                    reject(err);
                }
                else {
                    resolve(raw.buffer);
                }
            });
        });
    }
    static wc2ssl(algorithm) {
        const alg = algorithm.hash.name.toUpperCase().replace("-", "");
        return alg;
    }
}
