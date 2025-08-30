const crypto = require('crypto');

const LOWER = 'abcdefghijklmnopqrstuvwxyz';
const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const DIGITS = '0123456789';
const SYMBOLS = '!@#$%^&*()-_=+[]{};:,.<>?/\\|~';
const AMBIGUOUS = new Set([
    'O',
    '0',
    'o',
    'I',
    'l',
    '1',
    '|',
    '`',
    "'",
    '"',
    ';',
    '{',
    '}',
    '(',
    ')',
    '[',
    ']',
]);

function buildCharset({
    lowercase = true,
    uppercase = true,
    numbers = true,
    symbols = true,
    ambiguous = false,
}) {
    let pool = '';
    if (lowercase) pool += LOWER;
    if (uppercase) pool += UPPER;
    if (numbers) pool += DIGITS;
    if (symbols) pool += SYMBOLS;

    if (!ambiguous) {
        pool = [...pool].filter((ch) => !AMBIGUOUS.has(ch)).join('');
    }
    if (pool.length === 0) {
        throw new Error(
            'Character set is empty. Enable at least one category.'
        );
    }
    return pool;
}

function secureRandomString(length, charset) {
    const result = [];
    const chars = charset;
    const n = chars.length;
    const maxMultiple = Math.floor(256 / n) * n;

    while (result.length < length) {
        const buf = crypto.randomBytes(32); // batch
        for (let i = 0; i < buf.length && result.length < length; i++) {
            const x = buf[i];
            if (x < maxMultiple) {
                const idx = x % n;
                result.push(chars[idx]);
            }
        }
    }
    return result.join('');
}

function generatePassword(opts = {}) {
    const {
        length = 16,
        lowercase = true,
        uppercase = true,
        numbers = true,
        symbols = true,
        ambiguous = false,
    } = opts;

    if (length < 4 || length > 256) {
        throw new Error('Length must be between 4 and 256.');
    }

    const charset = buildCharset({
        lowercase,
        uppercase,
        numbers,
        symbols,
        ambiguous,
    });

    const needed = [];
    if (lowercase) needed.push(secureRandomString(1, LOWER));
    if (uppercase) needed.push(secureRandomString(1, UPPER));
    if (numbers) needed.push(secureRandomString(1, DIGITS));
    if (symbols) needed.push(secureRandomString(1, SYMBOLS));

    const remaining = Math.max(0, length - needed.length);
    const base = secureRandomString(remaining, charset) + needed.join('');

    return base
        .split('')
        .sort(() => crypto.randomBytes(1)[0] - 128)
        .join('');
}

module.exports = { generatePassword };
