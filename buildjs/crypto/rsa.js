"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var tslib_1 = require("tslib");
var webcrypto_core_1 = require("webcrypto-core");
var key_1 = require("../key");
var native = require("../native");
function b64_decode(b64url) {
    return new Buffer(webcrypto_core_1.Base64Url.decode(b64url));
}
var RsaCrypto = (function (_super) {
    tslib_1.__extends(RsaCrypto, _super);
    function RsaCrypto() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    RsaCrypto.generateKey = function (algorithm, extractable, keyUsages) {
        return new Promise(function (resolve, reject) {
            var size = algorithm.modulusLength;
            var exp = new Buffer(algorithm.publicExponent);
            var nExp = 0;
            if (exp.length === 3) {
                nExp = 1;
            }
            native.Key.generateRsa(size, nExp, function (err, key) {
                try {
                    if (err) {
                        reject(new webcrypto_core_1.WebCryptoError("Rsa: Can not generate new key\n" + err.message));
                    }
                    else {
                        var prvUsages = ["sign", "decrypt", "unwrapKey"]
                            .filter(function (usage) { return keyUsages.some(function (keyUsage) { return keyUsage === usage; }); });
                        var pubUsages = ["verify", "encrypt", "wrapKey"]
                            .filter(function (usage) { return keyUsages.some(function (keyUsage) { return keyUsage === usage; }); });
                        resolve({
                            privateKey: new key_1.CryptoKey(key, algorithm, "private", extractable, prvUsages),
                            publicKey: new key_1.CryptoKey(key, algorithm, "public", true, pubUsages),
                        });
                    }
                }
                catch (e) {
                    reject(e);
                }
            });
        });
    };
    RsaCrypto.importKey = function (format, keyData, algorithm, extractable, keyUsages) {
        var keyType = native.KeyType.PUBLIC;
        var alg = algorithm;
        return new Promise(function (resolve, reject) {
            var formatLC = format.toLocaleLowerCase();
            switch (formatLC) {
                case "jwk":
                    var jwk = keyData;
                    var data = {};
                    data["kty"] = jwk.kty;
                    data["n"] = b64_decode(jwk.n);
                    data["e"] = b64_decode(jwk.e);
                    if (jwk.d) {
                        keyType = native.KeyType.PRIVATE;
                        data["d"] = b64_decode(jwk.d);
                        data["p"] = b64_decode(jwk.p);
                        data["q"] = b64_decode(jwk.q);
                        data["dp"] = b64_decode(jwk.dp);
                        data["dq"] = b64_decode(jwk.dq);
                        data["qi"] = b64_decode(jwk.qi);
                    }
                    native.Key.importJwk(data, keyType, function (err, key) {
                        try {
                            if (err) {
                                reject(new webcrypto_core_1.WebCryptoError("ImportKey: Cannot import key from JWK\n" + err));
                            }
                            else {
                                resolve(key);
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
                        throw new webcrypto_core_1.WebCryptoError("ImportKey: keyData is not a Buffer");
                    }
                    var importFunction = native.Key.importSpki;
                    if (formatLC === "pkcs8") {
                        keyType = native.KeyType.PRIVATE;
                        importFunction = native.Key.importPkcs8;
                    }
                    importFunction(keyData, function (err, key) {
                        try {
                            if (err) {
                                reject(new webcrypto_core_1.WebCryptoError("ImportKey: Can not import key for " + format + "\n" + err.message));
                            }
                            else {
                                resolve(key);
                            }
                        }
                        catch (e) {
                            reject(e);
                        }
                    });
                    break;
                default:
                    throw new webcrypto_core_1.WebCryptoError("ImportKey: Wrong format value '" + format + "'");
            }
        })
            .then(function (key) {
            alg.modulusLength = key.modulusLength() << 3;
            alg.publicExponent = new Uint8Array(key.publicExponent());
            return new key_1.CryptoKey(key, alg, keyType ? "private" : "public", extractable, keyUsages);
        });
    };
    RsaCrypto.exportKey = function (format, key) {
        return new Promise(function (resolve, reject) {
            var nativeKey = key.native;
            var type = key.type === "public" ? native.KeyType.PUBLIC : native.KeyType.PRIVATE;
            switch (format.toLocaleLowerCase()) {
                case "jwk":
                    nativeKey.exportJwk(type, function (err, data) {
                        try {
                            var jwk = { kty: "RSA" };
                            jwk.key_ops = key.usages;
                            jwk.e = webcrypto_core_1.Base64Url.encode(data.e);
                            jwk.n = webcrypto_core_1.Base64Url.encode(data.n);
                            if (key.type === "private") {
                                jwk.d = webcrypto_core_1.Base64Url.encode(data.d);
                                jwk.p = webcrypto_core_1.Base64Url.encode(data.p);
                                jwk.q = webcrypto_core_1.Base64Url.encode(data.q);
                                jwk.dp = webcrypto_core_1.Base64Url.encode(data.dp);
                                jwk.dq = webcrypto_core_1.Base64Url.encode(data.dq);
                                jwk.qi = webcrypto_core_1.Base64Url.encode(data.qi);
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
                default:
                    throw new webcrypto_core_1.WebCryptoError("ExportKey: Unknown export format '" + format + "'");
            }
        });
    };
    RsaCrypto.wc2ssl = function (algorithm) {
        var alg = algorithm.hash.name.toUpperCase().replace("-", "");
        return alg;
    };
    return RsaCrypto;
}(webcrypto_core_1.BaseCrypto));
exports.RsaCrypto = RsaCrypto;
var RsaPKCS1 = (function (_super) {
    tslib_1.__extends(RsaPKCS1, _super);
    function RsaPKCS1() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    RsaPKCS1.exportKey = function (format, key) {
        return _super.exportKey.call(this, format, key)
            .then(function (jwk) {
            if (format === "jwk") {
                var reg = /(\d+)$/;
                jwk.alg = "RS" + reg.exec(key.algorithm.hash.name)[1];
                jwk.ext = true;
                if (key.type === "public") {
                    jwk.key_ops = ["verify"];
                }
            }
            return jwk;
        });
    };
    RsaPKCS1.sign = function (algorithm, key, data) {
        var _this = this;
        return new Promise(function (resolve, reject) {
            var alg = _this.wc2ssl(key.algorithm);
            var nativeKey = key.native;
            nativeKey.sign(alg, data, function (err, signature) {
                if (err) {
                    reject(new webcrypto_core_1.WebCryptoError("NativeError: " + err.message));
                }
                else {
                    resolve(signature.buffer);
                }
            });
        });
    };
    RsaPKCS1.verify = function (algorithm, key, signature, data) {
        var _this = this;
        return new Promise(function (resolve, reject) {
            var alg = _this.wc2ssl(key.algorithm);
            var nativeKey = key.native;
            nativeKey.verify(alg, data, signature, function (err, res) {
                if (err) {
                    reject(new webcrypto_core_1.WebCryptoError("NativeError: " + err.message));
                }
                else {
                    resolve(res);
                }
            });
        });
    };
    return RsaPKCS1;
}(RsaCrypto));
exports.RsaPKCS1 = RsaPKCS1;
var RsaPSS = (function (_super) {
    tslib_1.__extends(RsaPSS, _super);
    function RsaPSS() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    RsaPSS.sign = function (algorithm, key, data) {
        var _this = this;
        return new Promise(function (resolve, reject) {
            var alg = _this.wc2ssl(key.algorithm);
            var nativeKey = key.native;
            nativeKey.RsaPssSign(alg, algorithm.saltLength, data, function (err, signature) {
                if (err) {
                    reject(new webcrypto_core_1.WebCryptoError("NativeError: " + err.message));
                }
                else {
                    resolve(signature.buffer);
                }
            });
        });
    };
    RsaPSS.verify = function (algorithm, key, signature, data) {
        var _this = this;
        return new Promise(function (resolve, reject) {
            var alg = _this.wc2ssl(key.algorithm);
            var nativeKey = key.native;
            nativeKey.RsaPssVerify(alg, algorithm.saltLength, data, signature, function (err, res) {
                if (err) {
                    reject(new webcrypto_core_1.WebCryptoError("NativeError: " + err.message));
                }
                else {
                    resolve(res);
                }
            });
        });
    };
    RsaPSS.exportKey = function (format, key) {
        return _super.exportKey.call(this, format, key)
            .then(function (jwk) {
            if (format === "jwk") {
                var reg = /(\d+)$/;
                jwk.alg = "PS" + reg.exec(key.algorithm.hash.name)[1];
                jwk.ext = true;
                if (key.type === "public") {
                    jwk.key_ops = ["verify"];
                }
            }
            return jwk;
        });
    };
    return RsaPSS;
}(RsaCrypto));
exports.RsaPSS = RsaPSS;
var RsaOAEP = (function (_super) {
    tslib_1.__extends(RsaOAEP, _super);
    function RsaOAEP() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    RsaOAEP.exportKey = function (format, key) {
        return _super.exportKey.call(this, format, key)
            .then(function (jwk) {
            if (format === "jwk") {
                jwk.alg = "RSA-OAEP";
                var mdSize = /(\d+)$/.exec(key.algorithm.hash.name)[1];
                if (mdSize !== "1") {
                    jwk.alg += "-" + mdSize;
                }
                jwk.ext = true;
                if (key.type === "public") {
                    jwk.key_ops = ["encrypt", "wrapKey"];
                }
                else {
                    jwk.key_ops = ["decrypt", "unwrapKey"];
                }
            }
            return jwk;
        });
    };
    RsaOAEP.encrypt = function (algorithm, key, data) {
        return this.EncryptDecrypt(algorithm, key, data, false);
    };
    RsaOAEP.decrypt = function (algorithm, key, data) {
        return this.EncryptDecrypt(algorithm, key, data, true);
    };
    RsaOAEP.EncryptDecrypt = function (algorithm, key, data, type) {
        var _this = this;
        return new Promise(function (resolve, reject) {
            var alg = _this.wc2ssl(key.algorithm);
            var nativeKey = key.native;
            var label = null;
            if (algorithm.label) {
                label = new Buffer(algorithm.label);
            }
            nativeKey.RsaOaepEncDec(alg, data, label, type, function (err, res) {
                if (err) {
                    reject(new webcrypto_core_1.WebCryptoError("NativeError: " + err));
                }
                else {
                    resolve(res.buffer);
                }
            });
        });
    };
    return RsaOAEP;
}(RsaCrypto));
exports.RsaOAEP = RsaOAEP;
