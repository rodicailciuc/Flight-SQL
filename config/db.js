import path, { dirname } from 'path';
import { fileURLToPath } from 'url';

import mysql from 'mysql2/promise';
import dotenv from 'dotenv';

// construct path
const __filename = fileURLToPath(import.meta.url);
const PATH = dirname(__filename);

// load environment variables
dotenv.config({
    path: path.join(PATH, '..', '.env')
});

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    connectionLimit: 10
});

console.log('mysql connection pool created');

// Create query function
const query = async (sql, params) => {
    const connection = await pool.getConnection();

    try {
        const [results] = await connection.query(sql, params);
        return results;
    } catch (err) {
        console.error(err);
        return err;
    } finally {
        if (connection) {
            connection.release();
        }
    }
};

export default query;
