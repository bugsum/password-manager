const { Command } = require('commander');
const db = require('../db/database');
const { hashPassword, verifyPassword } = require('../security/hash');
const { encrypt, decrypt } = require('../security/encryption');

const program = new Command();

program
    .name('passman')
    .description('Secured Password Manager CLI')
    .version('0.1.0');

program
    .command('hello')
    .description('Test command')
    .action(() => {
        console.log('🔐 Password Manager CLI is working!');
    });

program
    .command('register <username> <password>')
    .description('Register a new user')
    .action(async (username, password) => {
        try {
            const passwordHash = await hashPassword(password);

            db.run(
                'INSERT INTO users (username, password_hash) VALUES (?, ?)',
                [username, passwordHash],
                function (err) {
                    if (err) {
                        console.error('❌ Error: Username may already exist.');
                    } else {
                        console.log(
                            `✅ User '${username}' registered successfully!`
                        );
                    }
                }
            );
        } catch (err) {
            console.error('❌ Registration failed:', err);
        }
    });

program
    .command('login <username> <password>')
    .description('Login with username and password')
    .action(async (username, password) => {
        try {
            db.get(
                'SELECT * FROM users WHERE username = ?',
                [username],
                async (err, row) => {
                    if (err) {
                        console.error('❌ Database error:', err);
                        return;
                    }
                    if (!row) {
                        console.error('❌ User not found.');
                        return;
                    }

                    const valid = await verifyPassword(
                        password,
                        row.password_hash
                    );
                    if (valid) {
                        console.log(
                            `✅ Login successful! Welcome, ${row.username}.`
                        );
                        console.log(`(Debug) Your user ID is ${row.id}`);
                    } else {
                        console.error('❌ Invalid password.');
                    }
                }
            );
        } catch (err) {
            console.error('❌ Login failed:', err);
        }
    });

program
    .command(
        'add <username> <masterPassword> <site> <siteUsername> <sitePassword>'
    )
    .description('Add a new credential to your vault')
    .action(
        async (username, masterPassword, site, siteUsername, sitePassword) => {
            db.get(
                'SELECT * FROM users WHERE username = ?',
                [username],
                async (err, row) => {
                    if (err || !row) {
                        console.error('❌ User not found.');
                        return;
                    }

                    const valid = await verifyPassword(
                        masterPassword,
                        row.password_hash
                    );
                    if (!valid) {
                        console.error('❌ Invalid master password.');
                        return;
                    }

                    const encryptedPass = encrypt(sitePassword, masterPassword);

                    db.run(
                        'INSERT INTO vault (user_id, site, site_username, site_password) VALUES (?, ?, ?, ?)',
                        [row.id, site, siteUsername, encryptedPass],
                        function (err) {
                            if (err) {
                                console.error(
                                    '❌ Error adding credential:',
                                    err
                                );
                            } else {
                                console.log(
                                    `✅ Stored credential for site '${site}'`
                                );
                            }
                        }
                    );
                }
            );
        }
    );

program
    .command('list <username> <masterPassword>')
    .description('List all stored credentials (without showing passwords)')
    .action(async (username, masterPassword) => {
        db.get(
            'SELECT * FROM users WHERE username = ?',
            [username],
            async (err, row) => {
                if (err || !row) {
                    console.error('❌ User not found.');
                    return;
                }

                const valid = await verifyPassword(
                    masterPassword,
                    row.password_hash
                );
                if (!valid) {
                    console.error('❌ Invalid master password.');
                    return;
                }

                db.all(
                    'SELECT site, site_username FROM vault WHERE user_id = ?',
                    [row.id],
                    (err, rows) => {
                        if (err) {
                            console.error('❌ Error fetching vault:', err);
                            return;
                        }
                        if (rows.length === 0) {
                            console.log('ℹ️ No credentials stored yet.');
                            return;
                        }

                        console.log('🔐 Stored Credentials:');
                        rows.forEach((r, i) => {
                            console.log(
                                `${i + 1}. Site: ${r.site}, Username: ${
                                    r.site_username
                                }`
                            );
                        });
                    }
                );
            }
        );
    });

program
    .command('get <username> <masterPassword> <site>')
    .description('Retrieve and decrypt password for a site')
    .action(async (username, masterPassword, site) => {
        db.get(
            'SELECT * FROM users WHERE username = ?',
            [username],
            async (err, row) => {
                if (err || !row) {
                    console.error('❌ User not found.');
                    return;
                }

                const valid = await verifyPassword(
                    masterPassword,
                    row.password_hash
                );
                if (!valid) {
                    console.error('❌ Invalid master password.');
                    return;
                }

                db.get(
                    'SELECT * FROM vault WHERE user_id = ? AND site = ?',
                    [row.id, site],
                    (err, entry) => {
                        if (err || !entry) {
                            console.error(
                                '❌ No credential found for that site.'
                            );
                            return;
                        }

                        try {
                            const decrypted = decrypt(
                                entry.site_password,
                                masterPassword
                            );
                            console.log(
                                `🔑 Password for '${site}' → ${decrypted}`
                            );
                        } catch (e) {
                            console.error(
                                '❌ Failed to decrypt password:',
                                e.message
                            );
                        }
                    }
                );
            }
        );
    });

program.parse(process.argv);
