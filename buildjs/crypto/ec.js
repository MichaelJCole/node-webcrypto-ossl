"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var tslib_1 = require("tslib");
var webcrypto = require("webcrypto-core");
var AlgorithmError = webcrypto.AlgorithmError;
var WebCryptoError = webcrypto.WebCryptoError;
var AlgorithmNames = webcrypto.AlgorithmNames;
var BaseCrypto = webcrypto.BaseCrypto;
var Base64Url = webcrypto.Base64Url;
var key_1 = require("../key");
var native = require("../native");
var aes = require("./aes");
function nc2ssl(nc) {
    var namedCurve = "";
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
        var pad = new Buffer(new Uint8Array(padSize - buf.length).map(function (v) { return 0; }));
        return Buffer.concat([pad, buf]);
    }
    return buf;
}
var EcCrypto = (function (_super) {
    tslib_1.__extends(EcCrypto, _super);
    function EcCrypto() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    EcCrypto.generateKey = function (algorithm, extractable, keyUsages) {
        return new Promise(function (resolve, reject) {
            var alg = algorithm;
            var namedCurve = nc2ssl(alg.namedCurve);
            native.Key.generateEc(namedCurve, function (err, key) {
                if (err) {
                    reject(err);
                }
                else {
                    var prvUsages = ["sign", "deriveKey", "deriveBits"]
                        .filter(function (usage) { return keyUsages.some(function (keyUsage) { return keyUsage === usage; }); });
                    var pubUsages = ["verify"]
                        .filter(function (usage) { return keyUsages.some(function (keyUsage) { return keyUsage === usage; }); });
                    resolve({
                        privateKey: new key_1.CryptoKey(key, algorithm, "private", extractable, prvUsages),
                        publicKey: new key_1.CryptoKey(key, algorithm, "public", true, pubUsages),
                    });
                }
            });
        });
    };
    EcCrypto.importKey = function (format, keyData, algorithm, extractable, keyUsages) {
        return new Promise(function (resolve, reject) {
            var formatLC = format.toLocaleLowerCase();
            var alg = algorithm;
            var data = {};
            var keyType = native.KeyType.PUBLIC;
            switch (formatLC) {
                case "raw":
                    if (!Buffer.isBuffer(keyData)) {
                        throw new WebCryptoError("ImportKey: keyData is not a Buffer");
                    }
                    if (!alg.namedCurve) {
                        throw new WebCryptoError("ImportKey: namedCurve property of algorithm parameter is required");
                    }
                    var keyLength = 0;
                    if (keyData.length === 65) {
                        keyLength = 32;
                    }
                    else if (keyData.length === 97) {
                        keyLength = 48;
                    }
                    else if (keyData.length === 133) {
                        keyLength = 66;
                    }
                    var x = keyData.slice(1, keyLength + 1);
                    var y = keyData.slice(keyLength + 1, (keyLength * 2) + 1);
                    data["kty"] = new Buffer("EC", "utf-8");
                    data["crv"] = nc2ssl(alg.namedCurve.toUpperCase());
                    data["x"] = b64_decode(Base64Url.encode(buf_pad(x, keyLength)));
                    data["y"] = b64_decode(Base64Url.encode(buf_pad(y, keyLength)));
                    native.Key.importJwk(data, keyType, function (err, key) {
                        try {
                            if (err) {
                                reject(new WebCryptoError("ImportKey: Cannot import key from JWK\n" + err));
                            }
                            else {
                                var ec = new key_1.CryptoKey(key, alg, keyType ? "private" : "public", extractable, keyUsages);
                                resolve(ec);
                            }
                        }
                        catch (e) {
                            reject(e);
                        }
                    });
                    break;
                case "jwk":
                    var jwk = keyData;
                    data["kty"] = jwk.kty;
                    data["crv"] = nc2ssl(jwk.crv);
                    data["x"] = b64_decode(jwk.x);
                    data["y"] = b64_decode(jwk.y);
                    if (jwk.d) {
                        keyType = native.KeyType.PRIVATE;
                        data["d"] = b64_decode(jwk.d);
                    }
                    native.Key.importJwk(data, keyType, function (err, key) {
                        try {
                            if (err) {
                                reject(new WebCryptoError("ImportKey: Cannot import key from JWK\n" + err));
                            }
                            else {
                                var ec = new key_1.CryptoKey(key, alg, keyType ? "private" : "public", extractable, keyUsages);
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
                    var importFunction = native.Key.importPkcs8;
                    if (formatLC === "spki") {
                        importFunction = native.Key.importSpki;
                    }
                    importFunction(keyData, function (err, key) {
                        try {
                            if (err) {
                                reject(new WebCryptoError("ImportKey: Can not import key for " + format + "\n" + err.message));
                            }
                            else {
                                var ec = new key_1.CryptoKey(key, alg, format.toLocaleLowerCase() === "spki" ? "public" : "private", extractable, keyUsages);
                                resolve(ec);
                            }
                        }
                        catch (e) {
                            reject(e);
                        }
                    });
                    break;
                default:
                    throw new WebCryptoError("ImportKey: Wrong format value '" + format + "'");
            }
        });
    };
    EcCrypto.exportKey = function (format, key) {
        return new Promise(function (resolve, reject) {
            var nativeKey = key.native;
            var type = key.type === "public" ? native.KeyType.PUBLIC : native.KeyType.PRIVATE;
            switch (format.toLocaleLowerCase()) {
                case "jwk":
                    nativeKey.exportJwk(type, function (err, data) {
                        try {
                            var jwk = { kty: "EC" };
                            jwk.crv = key.algorithm.namedCurve;
                            jwk.key_ops = key.usages;
                            var padSize = 0;
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
                                    throw new Error("Unsupported named curve '" + jwk.crv + "'");
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
                    nativeKey.exportSpki(function (err, raw) {
                        if (err) {
                            reject(err);
                        }
                        else {
                            resolve(raw.buffer);
                        }
                    });
                    break;
                case "pkcs8":
                    nativeKey.exportPkcs8(function (err, raw) {
                        if (err) {
                            reject(err);
                        }
                        else {
                            resolve(raw.buffer);
                        }
                    });
                    break;
                case "raw":
                    nativeKey.exportJwk(type, function (err, data) {
                        if (err) {
                            reject(err);
                        }
                        else {
                            var padSize = 0;
                            var crv = key.algorithm.namedCurve;
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
                                    throw new Error("Unsupported named curve '" + crv + "'");
                            }
                            var x = Base64Url.decode(Base64Url.encode(buf_pad(data.x, padSize)));
                            var y = Base64Url.decode(Base64Url.encode(buf_pad(data.y, padSize)));
                            var rawKey = new Uint8Array(1 + x.length + y.length);
                            rawKey.set([4]);
                            rawKey.set(x, 1);
                            rawKey.set(y, 1 + x.length);
                            resolve(rawKey.buffer);
                        }
                    });
                    break;
                default:
                    throw new WebCryptoError("ExportKey: Unknown export format '" + format + "'");
            }
        });
    };
    EcCrypto.sign = function (algorithm, key, data) {
        var _this = this;
        return new Promise(function (resolve, reject) {
            var alg = _this.wc2ssl(algorithm);
            var nativeKey = key.native;
            nativeKey.sign(alg, data, function (err, signature) {
                if (err) {
                    reject(new WebCryptoError("NativeError: " + err.message));
                }
                else {
                    resolve(signature.buffer);
                }
            });
        });
    };
    EcCrypto.verify = function (algorithm, key, signature, data) {
        var _this = this;
        return new Promise(function (resolve, reject) {
            var alg = _this.wc2ssl(algorithm);
            var nativeKey = key.native;
            nativeKey.verify(alg, data, signature, function (err, res) {
                if (err) {
                    reject(new WebCryptoError("NativeError: " + err.message));
                }
                else {
                    resolve(res);
                }
            });
        });
    };
    EcCrypto.deriveKey = function (algorithm, baseKey, derivedKeyType, extractable, keyUsages) {
        return new Promise(function (resolve, reject) {
            var algDerivedKeyType = derivedKeyType;
            var alg = algorithm;
            var AesClass;
            switch (algDerivedKeyType.name.toLowerCase()) {
                case AlgorithmNames.AesCBC.toLowerCase():
                case AlgorithmNames.AesGCM.toLowerCase():
                case AlgorithmNames.AesKW.toLowerCase():
                    AesClass = aes.AesCrypto;
                    break;
                default:
                    throw new AlgorithmError(AlgorithmError.NOT_SUPPORTED, algDerivedKeyType.name);
            }
            baseKey.native.EcdhDeriveKey(alg.public.native, algDerivedKeyType.length / 8, function (err, raw) {
                if (err) {
                    reject(err);
                }
                else {
                    AesClass.importKey("raw", raw, algDerivedKeyType, extractable, keyUsages)
                        .then(resolve, reject);
                }
            });
        });
    };
    EcCrypto.deriveBits = function (algorithm, baseKey, length) {
        return new Promise(function (resolve, reject) {
            var alg = algorithm;
            var nativeKey = baseKey.native;
            nativeKey.EcdhDeriveBits(alg.public.native, length, function (err, raw) {
                if (err) {
                    reject(err);
                }
                else {
                    resolve(raw.buffer);
                }
            });
        });
    };
    EcCrypto.wc2ssl = function (algorithm) {
        var alg = algorithm.hash.name.toUpperCase().replace("-", "");
        return alg;
    };
    return EcCrypto;
}(BaseCrypto));
exports.EcCrypto = EcCrypto;
