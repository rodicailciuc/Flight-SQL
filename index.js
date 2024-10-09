import path, { dirname } from 'path';
import { fileURLToPath } from 'url';

import express from 'express';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';

// import middlewares
import logger from './middleware/logger.js';

// import routes

// load environment variables
dotenv.config();
const PORT = process.env.PORT || 5003;

// construct path
const __filename = fileURLToPath(import.meta.url);
const PATH = dirname(__filename);

// initialize express
const app = express();

// parses
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// serve static files
app.use(express.static(path.join(PATH, 'public')));

// set view engine
app.set('view engine', 'ejs');
app.set('views', path.join(PATH, 'views'));

// use middlewares
app.use(logger);

// use routes

// handle 404
app.use('*', (req, res) => {
    res.status(404).render('404', { title: '404', message: 'Page not found' });
});

// handle errors
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).render('404', {
        title: '500',
        message: 'Internal server error'
    });
});

// listen to port
app.listen(PORT, () => {
    console.log(`server is up and running on port :  http://localhost:${PORT}`);
});
