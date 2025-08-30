const { Command } = require('commander');
const program = new Command();

program
    .name('passman')
    .description('Secured Password Manager CLI')
    .version('0.1.0');

program
    .command('hello')
    .description('tester command')
    .action(() => {
        console.log('Password Manager in action!');
    });

program.parse(process.argv);
