"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var tslib_1 = require("tslib");
var webcrypto = require("webcrypto-core");
var AlgorithmError = webcrypto.AlgorithmError;
var PrepareAlgorithm = webcrypto.PrepareAlgorithm;
var BaseCrypto = webcrypto.BaseCrypto;
var AlgorithmNames = webcrypto.AlgorithmNames;
var aes = require("./crypto/aes");
var ec = require("./crypto/ec");
var hmac = require("./crypto/hmac");
var pbkdf2 = require("./crypto/pbkdf2");
var rsa = require("./crypto/rsa");
var native = require("./native");
function PrepareData(data) {
    return ab2b(data);
}
function ab2b(ab) {
    if (Buffer.isBuffer(ab)) {
        return ab;
    }
    else if (ArrayBuffer.isView(ab)) {
        return Buffer.from(ab.buffer, ab.byteOffset, ab.byteLength);
    }
    else {
        return Buffer.from(ab);
    }
}
var SubtleCrypto = (function (_super) {
    tslib_1.__extends(SubtleCrypto, _super);
    function SubtleCrypto() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    SubtleCrypto.prototype.digest = function (algorithm, data) {
        return _super.prototype.digest.apply(this, arguments)
            .then(function () {
            return new Promise(function (resolve, reject) {
                var alg = PrepareAlgorithm(algorithm);
                var dataBytes = PrepareData(data);
                var algName = alg.name.toLowerCase();
                switch (algName) {
                    case "sha-1":
                    case "sha-224":
                    case "sha-256":
                    case "sha-384":
                    case "sha-512":
                        native.Core.digest(algName.replace("-", ""), dataBytes, function (err, digest) {
                            if (err) {
                                reject(err);
                            }
                            else {
                                resolve(digest.buffer);
                            }
                        });
                        break;
                    default:
                        throw new AlgorithmError(AlgorithmError.NOT_SUPPORTED, algName);
                }
            });
        });
    };
    SubtleCrypto.prototype.generateKey = function (algorithm, extractable, keyUsages) {
        return _super.prototype.generateKey.apply(this, arguments)
            .then(function () {
            var alg = PrepareAlgorithm(algorithm);
            var AlgClass;
            switch (alg.name.toLowerCase()) {
                case AlgorithmNames.RsaSSA.toLowerCase():
                    AlgClass = rsa.RsaPKCS1;
                    break;
                case AlgorithmNames.RsaPSS.toLowerCase():
                    AlgClass = rsa.RsaPSS;
                    break;
                case AlgorithmNames.RsaOAEP.toLowerCase():
                    AlgClass = rsa.RsaOAEP;
                    break;
                case AlgorithmNames.AesECB.toLowerCase():
                case AlgorithmNames.AesCBC.toLowerCase():
                case AlgorithmNames.AesCTR.toLowerCase():
                case AlgorithmNames.AesCTR.toLowerCase():
                case AlgorithmNames.AesGCM.toLowerCase():
                case AlgorithmNames.AesKW.toLowerCase():
                    AlgClass = aes.AesCrypto;
                    break;
                case AlgorithmNames.EcDSA.toLowerCase():
                case AlgorithmNames.EcDH.toLowerCase():
                    AlgClass = ec.EcCrypto;
                    break;
                case AlgorithmNames.Hmac.toLowerCase():
                    AlgClass = hmac.HmacCrypto;
                    break;
                default:
                    throw new AlgorithmError(AlgorithmError.NOT_SUPPORTED, alg.name);
            }
            return AlgClass.generateKey(alg, extractable, keyUsages);
        });
    };
    SubtleCrypto.prototype.sign = function (algorithm, key, data) {
        return _super.prototype.sign.apply(this, arguments)
            .then(function () {
            var alg = PrepareAlgorithm(algorithm);
            var dataBytes = PrepareData(data);
            var AlgClass;
            switch (alg.name.toLowerCase()) {
                case AlgorithmNames.RsaSSA.toLowerCase():
                    AlgClass = rsa.RsaPKCS1;
                    break;
                case AlgorithmNames.RsaPSS.toLowerCase():
                    AlgClass = rsa.RsaPSS;
                    break;
                case AlgorithmNames.EcDSA.toLowerCase():
                    AlgClass = ec.EcCrypto;
                    break;
                case AlgorithmNames.Hmac.toLowerCase():
                    AlgClass = hmac.HmacCrypto;
                    break;
                default:
                    throw new AlgorithmError(AlgorithmError.NOT_SUPPORTED, alg.name);
            }
            return AlgClass.sign(alg, key, dataBytes);
        });
    };
    SubtleCrypto.prototype.verify = function (algorithm, key, signature, data) {
        return _super.prototype.verify.apply(this, arguments)
            .then(function () {
            var alg = PrepareAlgorithm(algorithm);
            var signatureBytes = PrepareData(signature);
            var dataBytes = PrepareData(data);
            var AlgClass;
            switch (alg.name.toLowerCase()) {
                case AlgorithmNames.RsaSSA.toLowerCase():
                    AlgClass = rsa.RsaPKCS1;
                    break;
                case AlgorithmNames.RsaPSS.toLowerCase():
                    AlgClass = rsa.RsaPSS;
                    break;
                case AlgorithmNames.EcDSA.toLowerCase():
                    AlgClass = ec.EcCrypto;
                    break;
                case AlgorithmNames.Hmac.toLowerCase():
                    AlgClass = hmac.HmacCrypto;
                    break;
                default:
                    throw new AlgorithmError(AlgorithmError.NOT_SUPPORTED, alg.name);
            }
            return AlgClass.verify(alg, key, signatureBytes, dataBytes);
        });
    };
    SubtleCrypto.prototype.encrypt = function (algorithm, key, data) {
        return _super.prototype.encrypt.apply(this, arguments)
            .then(function () {
            var alg = PrepareAlgorithm(algorithm);
            var dataBytes = PrepareData(data);
            var AlgClass;
            switch (alg.name.toLowerCase()) {
                case AlgorithmNames.RsaOAEP.toLowerCase():
                    AlgClass = rsa.RsaOAEP;
                    break;
                case AlgorithmNames.AesECB.toLowerCase():
                case AlgorithmNames.AesCBC.toLowerCase():
                case AlgorithmNames.AesCTR.toLowerCase():
                case AlgorithmNames.AesGCM.toLowerCase():
                case AlgorithmNames.AesKW.toLowerCase():
                    AlgClass = aes.AesCrypto;
                    break;
                default:
                    throw new AlgorithmError(AlgorithmError.NOT_SUPPORTED, alg.name);
            }
            return AlgClass.encrypt(alg, key, dataBytes);
        });
    };
    SubtleCrypto.prototype.decrypt = function (algorithm, key, data) {
        return _super.prototype.decrypt.apply(this, arguments)
            .then(function () {
            var alg = PrepareAlgorithm(algorithm);
            var dataBytes = PrepareData(data);
            var AlgClass;
            switch (alg.name.toLowerCase()) {
                case AlgorithmNames.RsaOAEP.toLowerCase():
                    AlgClass = rsa.RsaOAEP;
                    break;
                case AlgorithmNames.AesECB.toLowerCase():
                case AlgorithmNames.AesCBC.toLowerCase():
                case AlgorithmNames.AesCTR.toLowerCase():
                case AlgorithmNames.AesGCM.toLowerCase():
                case AlgorithmNames.AesKW.toLowerCase():
                    AlgClass = aes.AesCrypto;
                    break;
                default:
                    throw new AlgorithmError(AlgorithmError.NOT_SUPPORTED, alg.name);
            }
            return AlgClass.decrypt(alg, key, dataBytes);
        });
    };
    SubtleCrypto.prototype.wrapKey = function (format, key, wrappingKey, wrapAlgorithm) {
        var _this = this;
        return _super.prototype.wrapKey.apply(this, arguments)
            .then(function () {
            return _this.exportKey(format, key)
                .then(function (exportedKey) {
                var alg = webcrypto.PrepareAlgorithm(wrapAlgorithm);
                var dataBytes;
                if (!(exportedKey instanceof ArrayBuffer)) {
                    dataBytes = new Buffer(JSON.stringify(exportedKey));
                }
                else {
                    dataBytes = new Buffer(exportedKey);
                }
                var CryptoClass;
                if (alg.name.toUpperCase() === webcrypto.AlgorithmNames.AesKW) {
                    CryptoClass = aes.AesCrypto;
                }
                if (CryptoClass) {
                    return CryptoClass.encrypt(alg, wrappingKey, dataBytes);
                }
                else {
                    return _this.encrypt(alg, wrappingKey, dataBytes);
                }
            });
        });
    };
    SubtleCrypto.prototype.unwrapKey = function (format, wrappedKey, unwrappingKey, unwrapAlgorithm, unwrappedKeyAlgorithm, extractable, keyUsages) {
        var _this = this;
        return _super.prototype.unwrapKey.apply(this, arguments)
            .then(function () {
            return Promise.resolve()
                .then(function () {
                var alg = webcrypto.PrepareAlgorithm(unwrapAlgorithm);
                var dataBytes = PrepareData(wrappedKey);
                var CryptoClass;
                if (alg.name.toUpperCase() === webcrypto.AlgorithmNames.AesKW) {
                    CryptoClass = aes.AesCrypto;
                }
                if (CryptoClass) {
                    return CryptoClass.decrypt(alg, unwrappingKey, dataBytes);
                }
                else {
                    return _this.decrypt(alg, unwrappingKey, dataBytes);
                }
            })
                .then(function (decryptedKey) {
                var keyData;
                if (format === "jwk") {
                    keyData = JSON.parse(new Buffer(decryptedKey).toString());
                }
                else {
                    keyData = new Buffer(decryptedKey);
                }
                return _this.importKey(format, keyData, unwrappedKeyAlgorithm, extractable, keyUsages);
            });
        });
    };
    SubtleCrypto.prototype.deriveKey = function (algorithm, baseKey, derivedKeyType, extractable, keyUsages) {
        return _super.prototype.deriveKey.apply(this, arguments)
            .then(function () {
            var alg = PrepareAlgorithm(algorithm);
            var algDerivedKeyType = PrepareAlgorithm(derivedKeyType);
            var AlgClass;
            switch (alg.name.toLowerCase()) {
                case AlgorithmNames.EcDH.toLowerCase():
                    AlgClass = ec.EcCrypto;
                    break;
                case AlgorithmNames.Pbkdf2.toLowerCase():
                    AlgClass = pbkdf2.Pbkdf2Crypto;
                    break;
                default:
                    throw new AlgorithmError(AlgorithmError.NOT_SUPPORTED, alg.name);
            }
            return AlgClass.deriveKey(alg, baseKey, algDerivedKeyType, extractable, keyUsages);
        });
    };
    SubtleCrypto.prototype.deriveBits = function (algorithm, baseKey, length) {
        return _super.prototype.deriveBits.apply(this, arguments)
            .then(function () {
            var alg = PrepareAlgorithm(algorithm);
            var AlgClass;
            switch (alg.name.toLowerCase()) {
                case AlgorithmNames.EcDH.toLowerCase():
                    AlgClass = ec.EcCrypto;
                    break;
                case AlgorithmNames.Pbkdf2.toLowerCase():
                    AlgClass = pbkdf2.Pbkdf2Crypto;
                    break;
                default:
                    throw new AlgorithmError(AlgorithmError.NOT_SUPPORTED, alg.name);
            }
            return AlgClass.deriveBits(alg, baseKey, length);
        });
    };
    SubtleCrypto.prototype.exportKey = function (format, key) {
        return _super.prototype.exportKey.apply(this, arguments)
            .then(function () {
            var AlgClass;
            switch (key.algorithm.name.toLowerCase()) {
                case AlgorithmNames.RsaSSA.toLowerCase():
                    AlgClass = rsa.RsaPKCS1;
                    break;
                case AlgorithmNames.RsaPSS.toLowerCase():
                    AlgClass = rsa.RsaPSS;
                    break;
                case AlgorithmNames.RsaOAEP.toLowerCase():
                    AlgClass = rsa.RsaOAEP;
                    break;
                case AlgorithmNames.AesECB.toLowerCase():
                case AlgorithmNames.AesCBC.toLowerCase():
                case AlgorithmNames.AesCTR.toLowerCase():
                case AlgorithmNames.AesGCM.toLowerCase():
                case AlgorithmNames.AesKW.toLowerCase():
                    AlgClass = aes.AesCrypto;
                    break;
                case AlgorithmNames.EcDSA.toLowerCase():
                case AlgorithmNames.EcDH.toLowerCase():
                    AlgClass = ec.EcCrypto;
                    break;
                case AlgorithmNames.Hmac.toLowerCase():
                    AlgClass = hmac.HmacCrypto;
                    break;
                default:
                    throw new AlgorithmError(AlgorithmError.NOT_SUPPORTED, key.algorithm.name);
            }
            return AlgClass.exportKey(format, key);
        });
    };
    SubtleCrypto.prototype.importKey = function (format, keyData, algorithm, extractable, keyUsages) {
        return _super.prototype.importKey.apply(this, arguments)
            .then(function () {
            var alg = PrepareAlgorithm(algorithm);
            var dataAny = keyData;
            if (format !== "jwk") {
                dataAny = PrepareData(dataAny);
            }
            var AlgClass;
            switch (alg.name.toLowerCase()) {
                case AlgorithmNames.RsaSSA.toLowerCase():
                    AlgClass = rsa.RsaPKCS1;
                    break;
                case AlgorithmNames.RsaPSS.toLowerCase():
                    AlgClass = rsa.RsaPSS;
                    break;
                case AlgorithmNames.RsaOAEP.toLowerCase():
                    AlgClass = rsa.RsaOAEP;
                    break;
                case AlgorithmNames.AesECB.toLowerCase():
                case AlgorithmNames.AesCBC.toLowerCase():
                case AlgorithmNames.AesCTR.toLowerCase():
                case AlgorithmNames.AesGCM.toLowerCase():
                case AlgorithmNames.AesKW.toLowerCase():
                    AlgClass = aes.AesCrypto;
                    break;
                case AlgorithmNames.EcDSA.toLowerCase():
                case AlgorithmNames.EcDH.toLowerCase():
                    AlgClass = ec.EcCrypto;
                    break;
                case AlgorithmNames.Hmac.toLowerCase():
                    AlgClass = hmac.HmacCrypto;
                    break;
                case AlgorithmNames.Pbkdf2.toLowerCase():
                    AlgClass = pbkdf2.Pbkdf2Crypto;
                    break;
                default:
                    throw new AlgorithmError(AlgorithmError.NOT_SUPPORTED, alg.name);
            }
            return AlgClass.importKey(format, dataAny, alg, extractable, keyUsages);
        });
    };
    return SubtleCrypto;
}(webcrypto.SubtleCrypto));
exports.SubtleCrypto = SubtleCrypto;
