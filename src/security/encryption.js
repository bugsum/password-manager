const crypto = require('crypto');

const ALGO = 'aes-256-gcm';
const IV_LENGTH = 16;

function deriveKey(masterPassword) {
    return crypto.createHash('sha256').update(masterPassword).digest();
}

function encrypt(text, masterPassword) {
    const iv = crypto.randomBytes(IV_LENGTH);
    const key = deriveKey(masterPassword);

    const cipher = crypto.createCipheriv(ALGO, key, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag().toString('hex');

    return `${iv.toString('hex')}:${authTag}:${encrypted}`;
}

function decrypt(encryptedData, masterPassword) {
    const [ivHex, authTagHex, encrypted] = encryptedData.split(':');

    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(authTagHex, 'hex');
    const key = deriveKey(masterPassword);

    const decipher = crypto.createDecipheriv(ALGO, key, iv);
    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

module.exports = { encrypt, decrypt };
