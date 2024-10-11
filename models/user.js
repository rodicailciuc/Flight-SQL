import query from '../config/db.js';

//create a new user table
const createUsersTable = async () => {
    const sqlQuery = `CREATE TABLE IF NOT EXISTS users (
            id INT PRIMARY KEY AUTO_INCREMENT,
            email VARCHAR(100) NOT NULL UNIQUE,
            password VARCHAR(100) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        );`;

    try {
        await query(sqlQuery);
        console.log('Users table created');
    } catch (err) {
        console.error(err);
    }
};

export default createUsersTable;
