import query from '../config/db.js';

//create flight tables
const createFlightsTable = async () => {
    const sqlQuery = `CREATE TABLE IF NOT EXISTS flights (
        id INT PRIMARY KEY AUTO_INCREMENT,
        from_flight VARCHAR(255) NOT NULL,
        to_flight VARCHAR(255) NOT NULL,
        date DATE NOT NULL,
        price DECIMAL(10,2) NOT NULL,
        company VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );`;

    try {
        await query(sqlQuery);
        console.log('Flights table created');
    } catch (err) {
        console.error(err);
    }
};

export default createFlightsTable;
