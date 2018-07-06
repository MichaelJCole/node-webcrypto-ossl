import * as fs from "fs";
import * as mkdirp from "mkdirp";
import * as path from "path";
import * as core from "webcrypto-core";
import { CryptoKey } from "./key";
import * as native from "./native";
const JSON_FILE_EXT = ".json";
class KeyStorageError extends core.WebCryptoError {
}
function jwkBufferToBase64(jwk) {
    const cpyJwk = jwk.keyJwk;
    for (const i in cpyJwk) {
        const attr = cpyJwk[i];
        if (Buffer.isBuffer(attr)) {
            cpyJwk[i] = attr.toString("base64");
        }
    }
    return jwk;
}
function jwkBase64ToBuffer(jwk) {
    const cpyJwk = jwk.keyJwk;
    const reserved = ["kty", "usage", "alg", "crv", "ext", "alg", "name"];
    for (const i in cpyJwk) {
        const attr = cpyJwk[i];
        if (reserved.indexOf(i) === -1 && typeof attr === "string") {
            try {
                const buf = new Buffer(attr, "base64");
                cpyJwk[i] = buf;
            }
            catch (e) {
            }
        }
    }
    return jwk;
}
export class KeyStorage {
    constructor(directory) {
        this.directory = "";
        this.keys = {};
        this.directory = directory;
        if (!fs.existsSync(directory)) {
            this.createDirectory(directory);
        }
        this.readDirectory();
    }
    clear() {
        if (!this.directory) {
            return;
        }
        this.keys = {};
        const items = fs.readdirSync(this.directory);
        items.forEach((item) => {
            if (item !== "." && item !== "..") {
                const file = path.join(this.directory, item);
                const stat = fs.statSync(file);
                if (stat.isFile) {
                    fs.unlinkSync(file);
                }
            }
        });
    }
    getItem(key) {
        let item = this.getItemById(key);
        if (!item) {
            return null;
        }
        item = jwkBase64ToBuffer(item);
        let res;
        let nativeKey;
        switch (item.type.toLowerCase()) {
            case "public":
                nativeKey = native.Key.importJwk(item.keyJwk, native.KeyType.PUBLIC);
                break;
            case "private":
                nativeKey = native.Key.importJwk(item.keyJwk, native.KeyType.PRIVATE);
                break;
            case "secret":
                throw new Error("Not implemented yet");
            default:
                throw new Error(`Unknown type '${item.type}'`);
        }
        res = new CryptoKey(nativeKey, item.algorithm, item.type, item.extractable, item.usages);
        return res;
    }
    key(index) {
        throw new Error("Not implemented yet");
    }
    removeItem(key) {
        const item = this.getItemById(key);
        if (item) {
            this.removeFile(item);
            delete this.keys[key];
        }
    }
    setItem(key, data) {
        const nativeKey = data.native;
        let jwk = null;
        switch (data.type.toLowerCase()) {
            case "public":
                jwk = nativeKey.exportJwk(native.KeyType.PUBLIC);
                break;
            case "private":
                jwk = nativeKey.exportJwk(native.KeyType.PRIVATE);
                break;
            case "secret":
                throw new Error("Not implemented yet");
            default:
                throw new Error(`Unsupported key type '${data.type}'`);
        }
        if (jwk) {
            let item = {
                algorithm: data.algorithm,
                usages: data.usages,
                type: data.type,
                keyJwk: jwk,
                name: key,
                extractable: data.extractable,
            };
            item = jwkBufferToBase64(item);
            this.saveFile(item);
            this.keys[key] = item;
        }
    }
    createDirectory(directory, flags) {
        mkdirp.sync(directory, flags);
    }
    readFile(file) {
        if (!fs.existsSync(file)) {
            throw new KeyStorageError(`File '${file}' is not exists`);
        }
        const fText = fs.readFileSync(file, "utf8");
        let json;
        try {
            json = JSON.parse(fText);
        }
        catch (e) {
            return null;
        }
        json.file = file;
        if (json.algorithm && json.type && json.usages && json.name) {
            return json;
        }
        return null;
    }
    readDirectory() {
        if (!this.directory) {
            throw new KeyStorageError("KeyStorage directory is not set");
        }
        this.keys = {};
        const items = fs.readdirSync(this.directory);
        items.forEach((item) => {
            if (item !== "." && item !== "..") {
                const file = path.join(this.directory, item);
                const stat = fs.statSync(file);
                if (stat.isFile) {
                    const key = this.readFile(file);
                    if (key) {
                        this.keys[key.name] = key;
                    }
                }
            }
        });
    }
    saveFile(key) {
        const json = JSON.stringify(key);
        fs.writeFileSync(path.join(this.directory, key.name + JSON_FILE_EXT), json, {
            encoding: "utf8",
            flag: "w",
        });
    }
    removeFile(key) {
        let file = key.file;
        if (!file) {
            file = path.join(this.directory, key.name + JSON_FILE_EXT);
        }
        if (fs.existsSync(file)) {
            fs.unlinkSync(file);
        }
    }
    get length() {
        return Object.keys(this.keys).length;
    }
    getItemById(id) {
        return this.keys[id] || null;
    }
}
