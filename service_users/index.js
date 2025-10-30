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
app.post('/users/register', async (req, res) => {
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
app.post('/users/login', async (req, res) => {
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

//Get profile
app.get('/users/me', authenticateToken, (req, res) => {
  try {
    const user = users.find(user => user.id === req.user.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const { passwordHash, ...userWithoutPassword } = user;
    res.json(userWithoutPassword);

  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// PUT profile
app.put('/users/profile', authenticateToken, async (req, res) => {
  try {
    // Валидация входных данных
    const { error, value } = updateProfileSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ 
        error: 'Validation failed', 
        details: error.details.map(d => d.message) 
      });
    }

    const userIndex = users.findIndex(user => user.id === req.user.userId);
    if (userIndex === -1) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Обновление полей
    users[userIndex] = {
      ...users[userIndex],
      ...value,
      updatedAt: new Date().toISOString()
    };

    const { passwordHash, ...updatedUser } = users[userIndex];
    
    res.json({
      success: true,
      message: 'Profile updated successfully',
      user: updatedUser
    });

  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/users', authenticateToken, requireAdmin, (req, res) => {
  try {
    // Pagination + filters params
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const emailFilter = req.query.email;
    const roleFilter = req.query.role;

    // Filtering
    let filteredUsers = [...users];
    
    if (emailFilter) {
      filteredUsers = filteredUsers.filter(user => 
        user.email.toLowerCase().includes(emailFilter.toLowerCase())
      );
    }
    
    if (roleFilter) {
      filteredUsers = filteredUsers.filter(user => 
        user.roles.includes(roleFilter)
      );
    }

    // Pagination
    const startIndex = (page - 1) * limit;
    const endIndex = page * limit;
    
    const paginatedUsers = filteredUsers.slice(startIndex, endIndex);
    
    // No passwords in response
    const usersWithoutPasswords = paginatedUsers.map(user => {
      const { passwordHash, ...userWithoutPassword } = user;
      return userWithoutPassword;
    });

    res.json({
      success: true,
      users: usersWithoutPasswords,
      pagination: {
        page,
        limit,
        total: filteredUsers.length,
        totalPages: Math.ceil(filteredUsers.length / limit)
      }
    });

  } catch (error) {
    console.error('Users list error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Health check
app.get('/users/health', (req, res) => {
  res.json({
    status: 'OK',
    service: 'Users Service',
    timestamp: new Date().toISOString()
  });
});

app.get('/users/status', (req, res) => {
  res.json({ status: 'Users service is running' });
});

// Получение пользователя по ID (для API Gateway)
app.get('/users/:userId', (req, res) => {
  const user = users.find(user => user.id === req.params.userId);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  const { passwordHash, ...userWithoutPassword } = user;
  res.json(userWithoutPassword);
});

// Test admin creation
const createTestAdmin = async () => {
  const adminExists = users.find(user => user.roles.includes('admin'));
  if (!adminExists) {
    const adminUser = {
      id: uuidv4(),
      email: 'admin@test.com',
      passwordHash: await hashPassword('admin123'),
      name: 'System Administrator',
      roles: ['admin', 'user'],
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
    users.push(adminUser);
    console.log('Test admin created: admin@test.com / admin123');
  }
};

// Start server
app.listen(PORT, '0.0.0.0', async () => {
  await createTestAdmin();
  console.log(`Users service running on port ${PORT}`);
});