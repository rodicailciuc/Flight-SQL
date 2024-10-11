import query from '../config/db.js';

const flightControllers = {
    getAllFlights: async (req, res) => {
        try {
            const sqlQuery = 'SELECT * FROM flights';
            const results = await query(sqlQuery);
            const { token } = req.cookies;
            res.status(200).render('flights', { flights: results, token });
        } catch (err) {
            console.error(err);
            res.status(500).render({
                title: 'Server error',
                message: 'Server error'
            });
        }
    },
    getFlightById: async (req, res) => {
        const { id } = req.params;

        const sqlQuery = `SELECT * FROM flights WHERE id=?`;
        const params = [id];

        const results = await query(sqlQuery, params);
        if (results.length > 0) {
            res.status(200).render('flight', { flight: results[0] });
        } else {
            res.status(404).render('404', {
                title: 'The flight does not exist',
                message: 'The flight does not exist'
            });
        }
    },
    addFlightForm: (req, res) => {
        res.status(200).render('add-flight-form');
    },
    addFlight: async (req, res) => {
        const { from, to, date, price, company } = req.body;

        if (from && to && date && price && company) {
            const sqlQuery = `INSERT INTO flights (from_flight, to_flight, date, price, company) VALUES (?, ?, ?, ?, ?)`;
            const params = [from, to, date, price, company];

            await query(sqlQuery, params);
            res.status(302).redirect('/api/flights');
        } else {
            res.status(400).render('404', {
                title: 'Invalid input',
                message: 'All fields should be filled in'
            });
        }
    },
    updateFlight: async (req, res) => {
        const { from, to, date, price, company } = req.body;
        const { id } = req.params;

        const sqlQuery = `UPDATE flights SET from_flight=?, to_flight=?, date=?, price=?, company=? WHERE id=?`;
        const params = [from, to, date, price, company, id];

        const results = await query(sqlQuery, params);

        if (results.affectedRows > 0) {
            res.status(302).redirect('/api/flights');
        } else {
            res.status(400).json({
                title: 'Flight not found',
                message: 'Flight not found'
            });
        }
    },
    deleteFlight: async (req, res) => {
        const { id } = req.params;

        const sqlQuery = `DELETE FROM flights WHERE id=?`;
        const params = [id];
        const results = await query(sqlQuery, params);

        if (results.affectedRows > 0) {
            res.status(302).redirect('/api/flights');
        } else {
            res.status(404).render('404', {
                title: 'Flight not found',
                message: 'Flight not found'
            });
        }
    }
};

export default flightControllers;
