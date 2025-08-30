const { Command } = require('commander');
const fs = require('fs');
const path = require('path');
const db = require('../db/database');
const { hashPassword, verifyPassword } = require('../security/hash');
const { encrypt, decrypt } = require('../security/encryption');
const { authUser } = require('../utils/auth');
const { generatePassword } = require('../utils/generator');

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

program
    .command('generate')
    .description('Generate a strong random password')
    .option('-l, --length <number>', 'password length (default 16)', '16')
    .option('--no-symbols', 'exclude symbols')
    .option('--no-numbers', 'exclude numbers')
    .option('--no-uppercase', 'exclude uppercase letters')
    .option('--no-lowercase', 'exclude lowercase letters')
    .option('--ambiguous', 'include visually ambiguous characters')
    .action((opts) => {
        const length = parseInt(opts.length, 10);
        try {
            const pwd = generatePassword({
                length,
                lowercase: opts.lowercase !== false,
                uppercase: opts.uppercase !== false,
                numbers: opts.numbers !== false,
                symbols: opts.symbols !== false,
                ambiguous: !!opts.ambiguous,
            });
            console.log(pwd);
        } catch (e) {
            console.error('❌ Generation failed:', e.message);
            process.exit(1);
        }
    });

program
    .command('export <username> <masterPassword> [outfile]')
    .description('Export your vault to an encrypted file')
    .action(async (username, masterPassword, outfile) => {
        try {
            const user = await authUser(username, masterPassword);

            db.all(
                'SELECT site, site_username, site_password FROM vault WHERE user_id = ?',
                [user.id],
                async (err, rows) => {
                    if (err) {
                        console.error('❌ Could not read vault:', err.message);
                        return;
                    }

                    const entries = [];
                    for (const r of rows) {
                        try {
                            const plain = decrypt(
                                r.site_password,
                                masterPassword
                            );
                            entries.push({
                                site: r.site,
                                site_username: r.site_username,
                                password: plain,
                            });
                        } catch (e) {
                            console.error(
                                `⚠️ Failed to decrypt an entry for ${r.site}: ${e.message}`
                            );
                        }
                    }

                    const payload = {
                        version: '1',
                        username,
                        exportedAt: new Date().toISOString(),
                        entries,
                    };

                    const plaintext = JSON.stringify(payload);
                    const cipher = encrypt(plaintext, masterPassword);

                    const exportObj = {
                        format: 'passman-export-v1',
                        cipher,
                    };

                    const ts = new Date().toISOString().replace(/[:.]/g, '-');
                    const filename =
                        outfile || `vault_export_${username}_${ts}.json`;
                    const outPath = path.resolve(process.cwd(), filename);

                    if (fs.existsSync(outPath)) {
                        console.error(
                            '❌ File already exists. Choose a different name.'
                        );
                        return;
                    }

                    fs.writeFileSync(
                        outPath,
                        JSON.stringify(exportObj, null, 2),
                        { encoding: 'utf8' }
                    );
                    console.log(
                        `✅ Exported ${entries.length} entr${
                            entries.length === 1 ? 'y' : 'ies'
                        } → ${outPath}`
                    );
                    console.log(
                        '🔒 The file is fully encrypted with your master password.'
                    );
                }
            );
        } catch (e) {
            console.error('❌ Export failed:', e.message);
        }
    });

program
    .command('import <username> <masterPassword> <file>')
    .description('Import an encrypted vault file and merge into your DB')
    .action(async (username, masterPassword, file) => {
        try {
            const user = await authUser(username, masterPassword);

            const filePath = path.resolve(process.cwd(), file);
            if (!fs.existsSync(filePath)) {
                console.error('❌ File not found:', filePath);
                return;
            }

            const raw = fs.readFileSync(filePath, 'utf8');
            let parsed;
            try {
                parsed = JSON.parse(raw);
            } catch {
                console.error('❌ Invalid file: not JSON.');
                return;
            }

            if (
                !parsed ||
                parsed.format !== 'passman-export-v1' ||
                typeof parsed.cipher !== 'string'
            ) {
                console.error('❌ Unsupported or corrupt export format.');
                return;
            }

            let plaintext;
            try {
                plaintext = decrypt(parsed.cipher, masterPassword);
            } catch (e) {
                console.error(
                    '❌ Could not decrypt file. Wrong master password?'
                );
                return;
            }

            let payload;
            try {
                payload = JSON.parse(plaintext);
            } catch {
                console.error('❌ Decrypted content is invalid JSON.');
                return;
            }

            const entries = Array.isArray(payload.entries)
                ? payload.entries
                : [];
            if (entries.length === 0) {
                console.log('ℹ️ No entries to import.');
                return;
            }

            let imported = 0;
            const stmt = db.prepare(
                'INSERT INTO vault (user_id, site, site_username, site_password) VALUES (?, ?, ?, ?)'
            );

            for (const e of entries) {
                if (
                    !e.site ||
                    !e.site_username ||
                    typeof e.password !== 'string'
                )
                    continue;
                const enc = encrypt(e.password, masterPassword);
                await new Promise((resolve) =>
                    stmt.run([user.id, e.site, e.site_username, enc], () =>
                        resolve()
                    )
                );
                imported++;
            }
            stmt.finalize();

            console.log(
                `✅ Imported ${imported} entr${
                    imported === 1 ? 'y' : 'ies'
                } into ${username}'s vault.`
            );
            console.log(
                '⚠️ Note: duplicates aren’t deduped yet. We’ll add smarter merge later.'
            );
        } catch (e) {
            console.error('❌ Import failed:', e.message);
        }
    });

program.parse(process.argv);
