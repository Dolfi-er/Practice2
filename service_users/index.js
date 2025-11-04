const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const Joi = require('joi');

const app = express();
const PORT = process.env.PORT || 8001;
const JWT_SECRET = process.env.JWT_SECRET || 'secret-key';

// Middleware
app.use(cors());
app.use(express.json());

// Имитация базы данных в памяти
let users = []; 

// Схемы валидации
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
    name: Joi.string().min(2).max(50),
    email: Joi.string().email()
});

// Middleware для аутентификации
const authenticateToken = (req, res, next) => { 
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({
            success: false,
            error: {
                code: 'UNAUTHORIZED',
                message: 'Access token required'
            }
        });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({
                success: false,
                error: {
                    code: 'INVALID_TOKEN',
                    message: 'Invalid or expired token'
                }
            });
        }
        req.user = user;
        next();
    });
};

// Middleware для проверки роли администратора
const requireAdmin = (req, res, next) => {
    if (!req.user.roles.includes('admin')) {
        return res.status(403).json({
            success: false,
            error: {
                code: 'FORBIDDEN',
                message: 'Admin access required'
            }
        });
    }
    next();
};

// Утилиты
const generateToken = (user) => {
    return jwt.sign(
        {
            userId: user.id,
            email: user.email,
            roles: user.roles
        },
        JWT_SECRET,
        { expiresIn: '2h' }
    );
};

const hashPassword = async (password) => {
    return await bcrypt.hash(password, 12);
};

const comparePassword = async (password, hash) => {
    return await bcrypt.compare(password, hash);
};

// Форматирование успешного ответа
const successResponse = (data, statusCode = 200) => {
    return {
        success: true,
        data: data
    };
};

// Форматирование ошибки
const errorResponse = (code, message, statusCode = 400) => {
    return {
        success: false,
        error: {
            code: code,
            message: message
        }
    };
};

// Routes

// Register (публичный)
app.post('/v1/users/register', async (req, res) => {
    try {
        // Data validation
        const { error, value } = registerSchema.validate(req.body);
        if (error) {
            return res.status(400).json(
                errorResponse(
                    'VALIDATION_ERROR',
                    'Invalid data',
                    { details: error.details.map(d => d.message) }
                )
            );
        }

        const { email, password, name } = value;

        // Existing user check
        const existingUser = users.find(u => u.email === email);
        if (existingUser) {
            return res.status(409).json(
                errorResponse(
                    'USER_EXISTS',
                    `User with email ${email} already exists`
                )
            );
        }

        // Hash password
        const hashedPassword = await hashPassword(password);

        // Create user
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

        // Token generation
        const token = generateToken(user);

        // Response without password
        const { passwordHash: _, ...userWithoutPassword } = user;

        res.status(201).json(
            successResponse({
                message: 'User registered successfully',
                user: userWithoutPassword,
                token
            })
        );

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json(
            errorResponse(
                'INTERNAL_ERROR',
                'Internal server error during registration'
            )
        );
    }
});

// Login (публичный)
app.post('/v1/users/login', async (req, res) => {
    try {
        // Data validation
        const { error, value } = loginSchema.validate(req.body);
        if (error) {
            return res.status(400).json(
                errorResponse(
                    'VALIDATION_ERROR',
                    'Validation failed',
                    { details: error.details.map(d => d.message) }
                )
            );
        }

        const { email, password } = value;

        // Find user by email
        const user = users.find(user => user.email === email);
        if (!user) {
            return res.status(401).json(
                errorResponse(
                    'AUTH_FAILED',
                    'Invalid email or password'
                )
            );
        }

        // Password validation
        const isPasswordValid = await comparePassword(password, user.passwordHash);
        if (!isPasswordValid) {
            return res.status(401).json(
                errorResponse(
                    'AUTH_FAILED',
                    'Invalid email or password'
                )
            );
        }

        // Token generation
        const token = generateToken(user);

        // Response without password
        const { passwordHash, ...userWithoutPassword } = user;

        res.json(
            successResponse({
                message: 'Login successful',
                user: userWithoutPassword,
                token
            })
        );

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json(
            errorResponse(
                'INTERNAL_ERROR',
                'Internal server error during login'
            )
        );
    }
});

// Get profile (защищенный)
app.get('/v1/users/me', authenticateToken, (req, res) => {
    try {
        const user = users.find(user => user.id === req.user.userId);
        if (!user) {
            return res.status(404).json(
                errorResponse('USER_NOT_FOUND', 'User not found')
            );
        }

        const { passwordHash, ...userWithoutPassword } = user;
        res.json(successResponse(userWithoutPassword));

    } catch (error) {
        console.error('Profile error:', error);
        res.status(500).json(
            errorResponse('INTERNAL_ERROR', 'Internal server error')
        );
    }
});

// Update profile (защищенный)
app.put('/v1/users/me', authenticateToken, async (req, res) => {
    try {
        const { error, value } = updateProfileSchema.validate(req.body);
        if (error) {
            return res.status(400).json(
                errorResponse(
                    'VALIDATION_ERROR',
                    'Validation failed',
                    { details: error.details.map(d => d.message) }
                )
            );
        }

        const userIndex = users.findIndex(user => user.id === req.user.userId);
        if (userIndex === -1) {
            return res.status(404).json(
                errorResponse('USER_NOT_FOUND', 'User not found')
            );
        }

        // Обновление полей
        users[userIndex] = {
            ...users[userIndex],
            ...value,
            updatedAt: new Date().toISOString()
        };

        const { passwordHash, ...updatedUser } = users[userIndex];

        res.json(
            successResponse({
                message: 'Profile updated successfully',
                user: updatedUser
            })
        );

    } catch (error) {
        console.error('Profile update error:', error);
        res.status(500).json(
            errorResponse('INTERNAL_ERROR', 'Internal server error')
        );
    }
});

// List users (admin only) 
app.get('/v1/users', authenticateToken, requireAdmin, (req, res) => {
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

        res.json(
            successResponse({
                users: usersWithoutPasswords,
                pagination: {
                    page,
                    limit,
                    total: filteredUsers.length,
                    totalPages: Math.ceil(filteredUsers.length / limit)
                }
            })
        );

    } catch (error) {
        console.error('Users list error:', error);
        res.status(500).json(
            errorResponse('INTERNAL_ERROR', 'Internal server error')
        );
    }
});

// Получение пользователя по ID (для API Gateway)
app.get('/v1/users/:userId', (req, res) => {
    const user = users.find(user => user.id === req.params.userId);
    if (!user) {
        return res.status(404).json(
            errorResponse('USER_NOT_FOUND', 'User not found')
        );
    }

    const { passwordHash, ...userWithoutPassword } = user;
    res.json(successResponse(userWithoutPassword));
});

// Health check (публичный)
app.get('/health', (req, res) => {
    res.json(
        successResponse({
            status: 'OK',
            service: 'Users Service',
            timestamp: new Date().toISOString()
        })
    );
});

app.get('/status', (req, res) => {
    res.json(successResponse({ status: 'Users service is running' }));
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

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json(
        errorResponse('ROUTE_NOT_FOUND', 'Route not found')
    );
});

// Start server
app.listen(PORT, '0.0.0.0', async () => {
    await createTestAdmin();
    console.log(`Users service running on port ${PORT}`);
});