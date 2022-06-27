'use strict';

// const crypto = require('crypto');
import * as crypto from "crypto-browserify";
// const fs = require('fs');


/**
 * Encrypts data and files using AES CBC/CFB - 128/192/256 bits. 
 * 
 * The encryption and authentication keys 
 * are derived from the supplied key/password using HKDF/PBKDF2.
 * The key can be set either with `setMasterKey` or with `randomKeyGen`.
 * Encrypted data format: salt[16] + iv[16] + ciphertext[n] + mac[32].
 * Ciphertext authenticity is verified with HMAC SHA256.
 * 
 * @property {Number} keyIterations The number of PBKDF2 iterations.
 * @property {Boolean} base64 Accepts ans returns base64 encoded data.
 */
class AesEncryption {
    /** Creates a new AesEncryption object.
     * @param {String} [mode=cbc] Optional, the AES mode (cbc or cfb)
     * @param {Number} [size=128] Optional, the key size (128, 192 or 256)
     * @throws {Error} if the mode is not supported or key size is invalid.
     */
    constructor(mode, size) {
        mode = (mode === undefined) ? 'cbc' : mode.toLowerCase();
        size = (size === undefined) ? 128 : size;

        if (!AES.Modes.hasOwnProperty(mode)) {
            throw Error(mode + ' is not supported!')
        }
        if (AES.Sizes.indexOf(size) == -1) {
            throw Error('Invalid key size!')
        }
        this._keyLen = size / 8;
        this._cipher = AES.Modes[mode].replace('size', size);
        this._masterKey = null;

        this.keyIterations = 20000;
        this.base64 = true;
    }

    /**
     * Encrypts data using a key or the supplied password.
     *
     * The password is not required if the master key has been set - 
     * either with `randomKeyGen` or with `setMasterKey`. 
     * If a password is supplied, it will be used to create a key with PBKDF2.
     * 
     * @param {(Buffer|String)} data The plaintext.
     * @param {String} [password=null] Optional, the password.
     * @return {(Buffer|String)} Encrypted data (salt + iv + ciphertext + mac).
     */
    encrypt(data, password) {
        const salt = randomBytes(saltLen);
        const iv = randomBytes(ivLen);
        try {
            const _keys = keys.call(this, salt, password);
            const aesKey = _keys[0], macKey = _keys[1];
            
            const aes = cipher.call(this, aesKey, iv, AES.Encrypt);
            const ciphertext = Buffer.concat(
                [iv, aes.update(data), aes.final()]
            );
            const mac = sign(ciphertext, macKey);
            let encrypted = Buffer.concat([salt, ciphertext, mac]);
            if (this.base64) {
                encrypted = encrypted.toString('base64');
            }
            return encrypted;
        } catch (err) {
            this._errorHandler(err);
            return null;
        }
    }

    /**
     * Decrypts data using a key or the supplied password.
     * 
     * The password is not required if the master key has been set - 
     * either with `randomKeyGen` or with `setMasterKey`. 
     * If a password is supplied, it will be used to create a key with PBKDF2.
     * 
     * @param {(Buffer|String)} data The ciphertext.
     * @param {String} [password=null] Optional, the password.
     * @return {(Buffer|String)} Plaintext.
     */
    decrypt(data, password) {
        try {
            if (this.base64) {
                data = Buffer.from(data, 'base64')
            }
            const salt = data.slice(0, saltLen);
            const iv = data.slice(saltLen, saltLen + ivLen);
            const ciphertext = data.slice(saltLen + ivLen, -macLen);
            const mac = data.slice(-macLen, data.length);

            const _keys = keys.call(this, salt, password);
            const aesKey = _keys[0], macKey = _keys[1];

            verify(Buffer.concat([iv, ciphertext]), mac, macKey);
            const aes = cipher.call(this, aesKey, iv, AES.Decrypt);
            const plaintext = Buffer.concat(
                [aes.update(ciphertext), aes.final()]
            );
            return plaintext;
        } catch (err) {
            this._errorHandler(err);
            return null;
        }
    }

    /**
     * Sets a new master key.
     * This key will be used to create the encryption and authentication keys.
     * 
     * @param {(Buffer|String)} key The new master key.
     * @param {Boolean} [raw=false] Optional, expexts raw bytes (not base64-encoded).
     */
    setMasterKey(key, raw) {
        try {
            key = (raw !== true) ? Buffer.from(key, 'base64') : key;
            if (!(key instanceof Buffer)) {
                throw Error('Key must be a Buffer!');
            }
            this._masterKey = key;
        } catch (err) {
            this._errorHandler(err);
        }
    }

    /**
     * Returns the master key (or null if the key is not set).
     * 
     * @param {Boolean} [raw=false] Optional, returns raw bytes (not base64-encoded).
     * @return {(Buffer|String)} The master key.
     */
    getMasterKey(raw) {
        if (this._masterKey === null) {
            this._errorHandler(new Error('The key is not set!'));
        } else if (raw !== true) {
            return this._masterKey.toString('base64');
        }
        return this._masterKey;
    }

    /**
     * Generates a new random key.
     * This key will be used to create the encryption and authentication keys.
     * 
     * @param {Number} [keyLen=32] Optional, the key size.
     * @param {Boolean} [raw=false] Optional, returns raw bytes (not base64-encoded).
     * @return {(Buffer|String)} The new master key.
     */
    randomKeyGen(keyLen, raw) {
        keyLen = (keyLen !== undefined) ? keyLen : 32;
        this._masterKey = randomBytes(keyLen);

        if (raw !== true) {
            return this._masterKey.toString('base64');
        }
        return this._masterKey;
    }

    /**
     * Handles exceptions (prints the error message by default).
     */
    _errorHandler(error) {
        console.log(error.message);
    }
}


module.exports = AesEncryption;


const saltLen = 16;
const ivLen = 16;
const macLen = 32;
const macKeyLen = 32;

const AES = {
    Modes: {'cbc': 'aes-size-cbc', 'cfb': 'aes-size-cfb8'}, 
    Sizes: [128, 192, 256], 
    Encrypt: 1,
    Decrypt: 2
};

/**
 * Creates random bytes, used for IV, salt and key generation.
 */
function randomBytes(size) {
    return crypto.randomBytes(size);
}

/**
 * Creates a crypto.cipher object, used for encryption.
 */
function cipher(key, iv, operation) {
    if (operation === AES.Encrypt) {
        return crypto.createCipheriv(this._cipher, key, iv);
    } else if (operation === AES.Decrypt) {
        return crypto.createDecipheriv(this._cipher, key, iv);
    } else {
        throw Error('Invalid operation!');
    }
}

/**
 * Derives encryption and authentication keys from a key or password.
 * If the password is not null, it will be used to create the keys.
 * 
 * @throws {Error} If neither the key or password is set.
 */
function keys(salt, password) {
    if (password !== undefined && password !== null) {
        var dkey = crypto.pbkdf2Sync(
            password, salt, this.keyIterations, this._keyLen + macKeyLen, 'sha512'
        );
    } else if (this._masterKey !== null) {
        var dkey = hkdfSha256(this._masterKey, this._keyLen + macKeyLen, salt)
    } else {
        throw Error('No password or key specified!');
    }
    return [
        dkey.slice(0, this._keyLen), 
        dkey.slice(this._keyLen, dkey.length)
    ]
}

/**
 * Computes the MAC of ciphertext, used for authentication.
 */
function sign(ciphertext, key) {
    const hmac = crypto.createHmac('sha256', key);
    hmac.update(ciphertext);
    return hmac.digest();
}

/**
 * Verifies the authenticity of ciphertext.
 * @throws {Error} if the MAC is invalid.
 */
function verify(ciphertext, mac, key) {
    const ciphertextMac = sign(ciphertext, key);
    if (!constantTimeComparison(mac, ciphertextMac)) {
        throw Error('Mac check failed!');
    }
}

/**
 * Computes the MAC of ciphertext, used for authentication.
 */
function signFile(path, key, fbeg, fend) {
    const hmac = crypto.createHmac('sha256', key);
    const chunks = fileChunks(path, fbeg, fend);
    do {
        var chunk = chunks.next();
        hmac.update(chunk.value || Buffer.alloc(0));
    } while (!chunk.done);
    return hmac.digest();
}

/**
 * Verifies the authenticity of ciphertext.
 * @throws {Error} if the MAC is invalid.
 */
function verifyFile(path, mac, key) {
    const fileMac = signFile(path, key, saltLen, macLen);
    if (!constantTimeComparison(mac, fileMac)) {
        throw Error('Mac check failed!');
    }
}

/**
 * Safely compares two byte arrays, used for ciphertext uthentication.
 */
function constantTimeComparison(macA, macB) {
    let result = macA.length ^ macB.length;
    for (let i=0; i<macA.length && i< macB.length; i++) {
        result |= macA[i] ^ macB[i];
    }
    return result === 0;
}

/**
 * A HKDF implementation, with HMAC SHA256.
 * Used for expanding the master key and derive AES and HMAC keys.
 * 
 * @param {Buffer} key The master key.
 * @param {Number} keySize The size of the derived key.
 * @param {Buffer} [salt=null] Optional, the salt (random bytes).
 * @param {Buffer} [info=null] Optional, information about the key.
 * @return {Buffer} Derived key material.
 */
function hkdfSha256(key, keySize, salt, info) {
    let dkey = Buffer.alloc(0);
    let hmac = crypto.createHmac('sha256', salt || '');
    const prk = hmac.update(key).digest();
    const hashLen = 32;

    for (let i = 0; i < Math.ceil(1.0 * keySize / hashLen); i++) {
        hmac = crypto.createHmac('sha256', prk);
        hmac.update(Buffer.concat([
            dkey.slice(dkey.length - hashLen), 
            Buffer.from(info || ''), Buffer.alloc(1, i + 1)
        ]));
        dkey = Buffer.concat([dkey, hmac.digest()]);
    }
    return dkey.slice(0, keySize);
}


