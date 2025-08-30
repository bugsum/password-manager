const { Command } = require('commander');
const db = require('../db/database');
const { hashPassword, verifyPassword } = require('../security/hash');

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

program.parse(process.argv);
