const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const Joi = require('joi');


const app = express();
const PORT = process.env.PORT || 8000;
const JWT_SECRET = process.env.JWT_SECRET || 'secret-key';

// Middleware
app.use(cors());
app.use(express.json());

// Имитация базы данных в памяти (LocalStorage)
let fakeUsersDb = {};
let currentId = 1;

//Схемы
const registerSchema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().min(4).required(),
    name: Joi.string().min(2).max(50).required()
});

const loginSchema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required()
});

const updateProfileSchema = Joi.object({
    name: Joi.string().min(2).max(50).required(),
    email: Joi.string().email().required()
});

//Authm middleware
const authMiddleware = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({error: 'Unauthorized'});
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({error: 'Invalid token'});
        }
        req.user = user;
        next();
    });
};

//Utils
const generateToken = (user) => {
    return jwt.sign(
        {
            userId: user.id,
            email: user.email,
            roles: user.roles
        },
        JWT_SECRET,
        {expiresIn: '2h'}
    );
};

// Routes
app.get('/users', (req, res) => {
    const users = Object.values(fakeUsersDb);
    res.json(users);
});

app.post('/users', (req, res) => {
    const userData = req.body;
    const userId = currentId++;

    const newUser = {
        id: userId,
        ...userData
    };

    fakeUsersDb[userId] = newUser;
    res.status(201).json(newUser);
});

app.get('/users/health', (req, res) => {
    res.json({
        status: 'OK',
        service: 'Users Service',
        timestamp: new Date().toISOString()
    });
});

app.get('/users/status', (req, res) => {
    res.json({status: 'Users service is running'});
});

app.get('/users/:userId', (req, res) => {
    const userId = parseInt(req.params.userId);
    const user = fakeUsersDb[userId];

    if (!user) {
        return res.status(404).json({error: 'User not found'});
    }

    res.json(user);
});

app.put('/users/:userId', (req, res) => {
    const userId = parseInt(req.params.userId);
    const updates = req.body;

    if (!fakeUsersDb[userId]) {
        return res.status(404).json({error: 'User not found'});
    }

    const updatedUser = {
        ...fakeUsersDb[userId],
        ...updates
    };

    fakeUsersDb[userId] = updatedUser;
    res.json(updatedUser);
});

app.delete('/users/:userId', (req, res) => {
    const userId = parseInt(req.params.userId);

    if (!fakeUsersDb[userId]) {
        return res.status(404).json({error: 'User not found'});
    }

    const deletedUser = fakeUsersDb[userId];
    delete fakeUsersDb[userId];

    res.json({message: 'User deleted', deletedUser});
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Users service running on port ${PORT}`);
});