const db = require('../db/database');
const { verifyPassword } = require('../security/hash');

function authUser(username, masterPassword) {
    return new Promise((resolve, reject) => {
        db.get(
            'SELECT * FROM users WHERE username = ?',
            [username],
            async (err, row) => {
                if (err)
                    return reject(new Error('Database error: ' + err.message));
                if (!row) return reject(new Error('User not found'));
                try {
                    const ok = await verifyPassword(
                        masterPassword,
                        row.password_hash
                    );
                    if (!ok)
                        return reject(new Error('Invalid master password'));
                    resolve(row);
                } catch (e) {
                    reject(e);
                }
            }
        );
    });
}

module.exports = { authUser };
