const { Command } = require('commander');
const db = require('../db/database');
const { hashPassword } = require('../security/hash');

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

program.parse(process.argv);
