const mysql = require('mysql2/promise');

const pool = mysql.createPool({
    host: '127.0.0.1',
    user: 'root',
    password: '',
    database: 'pjatk',
});

pool.getConnection()
    .then(() => console.log('Połączono z bazą danych!'))
    .catch((err) => console.error('Błąd połączenia z bazą danych:', err));

module.exports = pool;
