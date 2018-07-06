export class CryptoKey {
    constructor(key, alg, type, extractable, keyUsages) {
        this.usages = [];
        this.native_ = key;
        this.extractable = extractable;
        this.algorithm = alg;
        this.type = type;
        this.usages = keyUsages;
    }
    get native() {
        return this.native_;
    }
}
