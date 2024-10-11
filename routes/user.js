import express from 'express';

import userControllers from '../controllers/user.js';

const router = express.Router();

const { register, login, logout, getRegisterForm, getLoginForm } =
    userControllers;

router.get('/login', getLoginForm);
router.post('/login', login);
router.get('/register', getRegisterForm);
router.post('/register', register);
router.get('/logout', logout);

export default router;
