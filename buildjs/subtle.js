import * as webcrypto from "webcrypto-core";
const AlgorithmError = webcrypto.AlgorithmError;
const PrepareAlgorithm = webcrypto.PrepareAlgorithm;
const BaseCrypto = webcrypto.BaseCrypto;
const AlgorithmNames = webcrypto.AlgorithmNames;
import * as aes from "./crypto/aes";
import * as ec from "./crypto/ec";
import * as hmac from "./crypto/hmac";
import * as pbkdf2 from "./crypto/pbkdf2";
import * as rsa from "./crypto/rsa";
import * as native from "./native";
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
export class SubtleCrypto extends webcrypto.SubtleCrypto {
    digest(algorithm, data) {
        return super.digest.apply(this, arguments)
            .then(() => {
            return new Promise((resolve, reject) => {
                const alg = PrepareAlgorithm(algorithm);
                const dataBytes = PrepareData(data);
                const algName = alg.name.toLowerCase();
                switch (algName) {
                    case "sha-1":
                    case "sha-224":
                    case "sha-256":
                    case "sha-384":
                    case "sha-512":
                        native.Core.digest(algName.replace("-", ""), dataBytes, (err, digest) => {
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
    }
    generateKey(algorithm, extractable, keyUsages) {
        return super.generateKey.apply(this, arguments)
            .then(() => {
            const alg = PrepareAlgorithm(algorithm);
            let AlgClass;
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
    }
    sign(algorithm, key, data) {
        return super.sign.apply(this, arguments)
            .then(() => {
            const alg = PrepareAlgorithm(algorithm);
            const dataBytes = PrepareData(data);
            let AlgClass;
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
    }
    verify(algorithm, key, signature, data) {
        return super.verify.apply(this, arguments)
            .then(() => {
            const alg = PrepareAlgorithm(algorithm);
            const signatureBytes = PrepareData(signature);
            const dataBytes = PrepareData(data);
            let AlgClass;
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
    }
    encrypt(algorithm, key, data) {
        return super.encrypt.apply(this, arguments)
            .then(() => {
            const alg = PrepareAlgorithm(algorithm);
            const dataBytes = PrepareData(data);
            let AlgClass;
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
    }
    decrypt(algorithm, key, data) {
        return super.decrypt.apply(this, arguments)
            .then(() => {
            const alg = PrepareAlgorithm(algorithm);
            const dataBytes = PrepareData(data);
            let AlgClass;
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
    }
    wrapKey(format, key, wrappingKey, wrapAlgorithm) {
        return super.wrapKey.apply(this, arguments)
            .then(() => {
            return this.exportKey(format, key)
                .then((exportedKey) => {
                const alg = webcrypto.PrepareAlgorithm(wrapAlgorithm);
                let dataBytes;
                if (!(exportedKey instanceof ArrayBuffer)) {
                    dataBytes = new Buffer(JSON.stringify(exportedKey));
                }
                else {
                    dataBytes = new Buffer(exportedKey);
                }
                let CryptoClass;
                if (alg.name.toUpperCase() === webcrypto.AlgorithmNames.AesKW) {
                    CryptoClass = aes.AesCrypto;
                }
                if (CryptoClass) {
                    return CryptoClass.encrypt(alg, wrappingKey, dataBytes);
                }
                else {
                    return this.encrypt(alg, wrappingKey, dataBytes);
                }
            });
        });
    }
    unwrapKey(format, wrappedKey, unwrappingKey, unwrapAlgorithm, unwrappedKeyAlgorithm, extractable, keyUsages) {
        return super.unwrapKey.apply(this, arguments)
            .then(() => {
            return Promise.resolve()
                .then(() => {
                const alg = webcrypto.PrepareAlgorithm(unwrapAlgorithm);
                const dataBytes = PrepareData(wrappedKey);
                let CryptoClass;
                if (alg.name.toUpperCase() === webcrypto.AlgorithmNames.AesKW) {
                    CryptoClass = aes.AesCrypto;
                }
                if (CryptoClass) {
                    return CryptoClass.decrypt(alg, unwrappingKey, dataBytes);
                }
                else {
                    return this.decrypt(alg, unwrappingKey, dataBytes);
                }
            })
                .then((decryptedKey) => {
                let keyData;
                if (format === "jwk") {
                    keyData = JSON.parse(new Buffer(decryptedKey).toString());
                }
                else {
                    keyData = new Buffer(decryptedKey);
                }
                return this.importKey(format, keyData, unwrappedKeyAlgorithm, extractable, keyUsages);
            });
        });
    }
    deriveKey(algorithm, baseKey, derivedKeyType, extractable, keyUsages) {
        return super.deriveKey.apply(this, arguments)
            .then(() => {
            const alg = PrepareAlgorithm(algorithm);
            const algDerivedKeyType = PrepareAlgorithm(derivedKeyType);
            let AlgClass;
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
    }
    deriveBits(algorithm, baseKey, length) {
        return super.deriveBits.apply(this, arguments)
            .then(() => {
            const alg = PrepareAlgorithm(algorithm);
            let AlgClass;
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
    }
    exportKey(format, key) {
        return super.exportKey.apply(this, arguments)
            .then(() => {
            let AlgClass;
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
    }
    importKey(format, keyData, algorithm, extractable, keyUsages) {
        return super.importKey.apply(this, arguments)
            .then(() => {
            const alg = PrepareAlgorithm(algorithm);
            let dataAny = keyData;
            if (format !== "jwk") {
                dataAny = PrepareData(dataAny);
            }
            let AlgClass;
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
    }
}
