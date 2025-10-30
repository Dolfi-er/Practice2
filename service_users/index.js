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


//Auth middleware
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

const hashPassword = async (password) => {
    return await bcrypt.hash(password, 12);
};

const comparePassword = async (password, hash) => {
    return await bcrypt.compare(password, hash);
};


// Routes

//Register
app.post('/register', async (req, res) => {
    try{
        //Data validation
        const {error, value} = registerSchema.validate(req.body);
        if (error) {
            return res.status(400).json({
                error: 'Invalid data',
                details: error.details.map(d => d.message)
            });
        }

        const { email, password, name } = value;

        //Existing user check
        const existingUser = users.find(u => u.email === email);
        if (existingUser) {
            return res.status(409).json({
                error: 'User already exists',
                details: ['User with email ' + email + ' already exists']
            });
        }

        //Hash password
        const hashedPassword = await hashPassword(password);

        //Create user
        const user = {
            id: uuidv4(),
            email,
            passwordHash: hashedPassword,
            name,
            roles: ['user'],
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
        };

        users.push(user);

        //Token generation
        const token = generateToken(user);

        //Response without password
        const { passwordHash: _, ...userWithoutPassword } = user;

        res.status(201).json({
            success: true,
            message: 'User registered successfully',
            user: userWithoutPassword,
            token
        });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ 
            error: 'Internal server error during registration' 
        });
    }
});

//Login
app.post('/login', async (req, res) => {
  try {
    //Data validation
    const { error, value } = loginSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ 
        error: 'Validation failed', 
        details: error.details.map(d => d.message) 
      });
    }

    const { email, password } = value;

    // Find user by email
    const user = users.find(user => user.email === email);
    if (!user) {
      return res.status(401).json({ 
        error: 'Authentication failed',
        message: 'Invalid email or password' 
      });
    }

    // Password validation
    const isPasswordValid = await comparePassword(password, user.passwordHash);
    if (!isPasswordValid) {
      return res.status(401).json({ 
        error: 'Authentication failed',
        message: 'Invalid email or password' 
      });
    }

    // Token generation
    const token = generateToken(user);

    //Response without password
    const { passwordHash, ...userWithoutPassword } = user;

    res.json({
      success: true,
      message: 'Login successful',
      user: userWithoutPassword,
      token
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ 
      error: 'Internal server error during login' 
    });
  }
});

app.get('/users', (req, res) => {
    const users = Object.values(fakeUsersDb);
    res.json(users);
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