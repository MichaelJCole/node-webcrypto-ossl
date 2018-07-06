import * as Core from "webcrypto-core";
import { CryptoKey } from "../key";
import * as native from "../native";
import { AesCrypto } from "./aes";
import { HmacCrypto } from "./hmac";
function b64_decode(b64url) {
    return new Buffer(Core.Base64Url.decode(b64url));
}
export class Pbkdf2Crypto extends Core.BaseCrypto {
    static importKey(format, keyData, algorithm, extractable, keyUsages) {
        return new Promise((resolve, reject) => {
            const formatLC = format.toLocaleLowerCase();
            const alg = algorithm;
            alg.name = alg.name.toUpperCase();
            let raw;
            switch (formatLC) {
                case "jwk":
                    raw = b64_decode(keyData.k);
                    break;
                case "raw":
                    raw = keyData;
                    break;
                default:
                    throw new Core.WebCryptoError(`ImportKey: Wrong format value '${format}'`);
            }
            alg.length = raw.byteLength * 8;
            native.Pbkdf2Key.importKey(raw, (err, key) => {
                if (err) {
                    reject(err);
                }
                else {
                    resolve(new CryptoKey(key, algorithm, "secret", extractable, keyUsages));
                }
            });
        });
    }
    static deriveKey(algorithm, baseKey, derivedKeyType, extractable, keyUsages) {
        return Promise.resolve()
            .then(() => {
            return this.deriveBits(algorithm, baseKey, derivedKeyType.length);
        })
            .then((raw) => {
            let CryptoClass;
            switch (derivedKeyType.name.toUpperCase()) {
                case Core.AlgorithmNames.AesCBC:
                case Core.AlgorithmNames.AesGCM:
                case Core.AlgorithmNames.AesKW:
                    CryptoClass = AesCrypto;
                    break;
                case Core.AlgorithmNames.Hmac:
                    CryptoClass = HmacCrypto;
                    break;
                default:
                    throw new Core.AlgorithmError(Core.AlgorithmError.UNSUPPORTED_ALGORITHM, algorithm.name);
            }
            return CryptoClass.importKey("raw", new Buffer(raw), derivedKeyType, extractable, keyUsages);
        });
    }
    static deriveBits(algorithm, baseKey, length) {
        return new Promise((resolve, reject) => {
            const alg = algorithm;
            const nativeKey = baseKey.native;
            const hash = Core.PrepareAlgorithm(alg.hash);
            const salt = new Buffer(Core.PrepareData(alg.salt, "salt"));
            nativeKey.deriveBits(this.wc2ssl(hash), salt, alg.iterations, length, (err, raw) => {
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
        const alg = algorithm.name.toUpperCase().replace("-", "");
        return alg;
    }
}
