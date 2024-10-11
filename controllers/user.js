import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

import validateEmail from '../utils/validateEmail.js';
import validatePassword from '../utils/validatePassword.js';
import hashPassword from '../utils/hashPassword.js';
import matchPassword from '../utils/matchPasswords.js';

import query from '../config/db.js';
import createUsersTable from '../models/user.js';

const userControllers = {
    register: async (req, res) => {
        const { email, password, rePassword } = req.body;
        //check if email already exists
        const checkEmailQuery = `SELECT * FROM users WHERE email=?`;
        const checkEmailParams = [email];
        const result = await query(checkEmailQuery, checkEmailParams);
        if (result.length > 0) {
            return res.status(400).render('404', {
                title: 'Email already exists',
                message: 'Email already exist, please register'
            });
        }
        //validate the email, password and check if the passwords match
        const isEmailValid = validateEmail(email);
        const isPasswordValid = validatePassword(password);
        const doPasswordsMatch = matchPassword(password, rePassword);

        if (isEmailValid && isPasswordValid && doPasswordsMatch) {
            //hash the password
            const hashedPassword = hashPassword(password);
            //create user

            const sqlQuery = `INSERT INTO users (email, password) VALUES (?, ?)`;
            const params = [email, hashedPassword];
            const results = await query(sqlQuery, params);
            if (results.affectedRows > 0) {
                //redirect to login
                return res.status(302).redirect('/api/login');
            } else {
                return res.status(400).render('404', {
                    title: 'Incorrect email or password',
                    message: 'Incorrect email or password'
                });
            }
        }
    },
    login: async (req, res) => {
        const { email, password } = req.body;
        //check if the email exist

        const sqlQuery = `SELECT * FROM users WHERE email=?`;
        const params = [email];
        const results = await query(sqlQuery, params);

        if (results.length === 0) {
            return res.status(400).render('404', {
                title: 'Email does not exist',
                message: 'Email does not exist, please register'
            });
        }
        //check if the password is correct
        bcrypt.compare(password, results[0].password, (err, isValid) => {
            if (err) {
                console.error(err);
            }

            if (!isValid) {
                return res.status(400).render('404', {
                    title: 'Invalid password or email',
                    message: 'Invalid password or email'
                });
            }
            // create token
            const token = jwt.sign({ email }, process.env.TOKEN_SECRET);
            //set cookie
            res.cookie('token', token, { httpOnly: true });
            res.status(302).redirect('/api/flights');
        });
    },
    logout: (req, res) => {
        res.clearCookie('token');
        res.status(302).redirect('/api/login');
    },
    getRegisterForm: (req, res) => {
        res.status(200).render('register-form');
    },
    getLoginForm: (req, res) => {
        res.status(200).render('login-form');
    }
};

export default userControllers;
