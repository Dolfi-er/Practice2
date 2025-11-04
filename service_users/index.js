const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const Joi = require('joi');
const pino = require('pino');
const pinoHttp = require('pino-http');

const app = express();
const PORT = process.env.PORT || 8001;
const JWT_SECRET = process.env.JWT_SECRET || 'secret-key';

// Logger configuration
const logger = pino({
  level: process.env.LOG_LEVEL || 'info',
  formatters: {
    level: (label) => {
      return { level: label };
    },
    bindings: (bindings) => {
      return {
        pid: bindings.pid,
        hostname: bindings.hostname,
        service: 'users-service'
      };
    }
  },
  timestamp: pino.stdTimeFunctions.isoTime
});

// HTTP logger middleware
const httpLogger = pinoHttp({
  logger: logger,
  genReqId: (req) => req.headers['x-request-id'] || uuidv4(),
  customLogLevel: (req, res, err) => {
    if (res.statusCode >= 400 && res.statusCode < 500) {
      return 'warn';
    } else if (res.statusCode >= 500) {
      return 'error';
    }
    return 'info';
  }
});

// Middleware
app.use(cors());
app.use(express.json());
app.use(httpLogger);

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
        req.log.warn('Authentication failed: missing token');
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
            req.log.warn({ err: err.message }, 'Authentication failed: invalid token');
            return res.status(403).json({
                success: false,
                error: {
                    code: 'INVALID_TOKEN',
                    message: 'Invalid or expired token'
                }
            });
        }
        req.user = user;
        req.log.info({ userId: user.userId }, 'User authenticated');
        next();
    });
};

// Middleware для проверки роли администратора
const requireAdmin = (req, res, next) => {
    if (!req.user.roles.includes('admin')) {
        req.log.warn({ userId: req.user.userId }, 'Admin access required');
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

// Middleware для внутренних сервисных запросов
const allowInternalRequests = (req, res, next) => {
    if (req.headers['x-internal-request'] === 'true') {
        req.isInternalRequest = true;
    }
    next();
};

app.use(allowInternalRequests);

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
const errorResponse = (code, message, details = null) => {
    const error = {
        code: code,
        message: message
    };
    if (details) {
        error.details = details;
    }
    return {
        success: false,
        error: error
    };
};

// Routes

// Register (публичный)
app.post('/v1/users/register', async (req, res) => {
    try {
        req.log.debug({ body: req.body }, 'Registration attempt');

        // Data validation
        const { error, value } = registerSchema.validate(req.body);
        if (error) {
            req.log.warn({ error: error.details }, 'Registration validation failed');
            return res.status(400).json(
                errorResponse(
                    'VALIDATION_ERROR',
                    'Invalid data',
                    error.details.map(d => d.message)
                )
            );
        }

        const { email, password, name } = value;

        // Existing user check
        const existingUser = users.find(u => u.email === email);
        if (existingUser) {
            req.log.warn({ email: email }, 'User already exists');
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

        req.log.info({ userId: user.id, email: user.email }, 'User registered successfully');

        res.status(201).json(
            successResponse({
                message: 'User registered successfully',
                user: userWithoutPassword,
                token
            })
        );

    } catch (error) {
        req.log.error({ err: error }, 'Registration error');
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
        req.log.debug({ email: req.body.email }, 'Login attempt');

        // Data validation
        const { error, value } = loginSchema.validate(req.body);
        if (error) {
            req.log.warn({ error: error.details }, 'Login validation failed');
            return res.status(400).json(
                errorResponse(
                    'VALIDATION_ERROR',
                    'Validation failed',
                    error.details.map(d => d.message)
                )
            );
        }

        const { email, password } = value;

        // Find user by email
        const user = users.find(user => user.email === email);
        if (!user) {
            req.log.warn({ email: email }, 'Login failed: user not found');
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
            req.log.warn({ email: email }, 'Login failed: invalid password');
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

        req.log.info({ userId: user.id, email: user.email }, 'User logged in successfully');

        res.json(
            successResponse({
                message: 'Login successful',
                user: userWithoutPassword,
                token
            })
        );

    } catch (error) {
        req.log.error({ err: error }, 'Login error');
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
            req.log.warn({ userId: req.user.userId }, 'User not found');
            return res.status(404).json(
                errorResponse('USER_NOT_FOUND', 'User not found')
            );
        }

        const { passwordHash, ...userWithoutPassword } = user;
        
        req.log.debug({ userId: user.id }, 'Profile retrieved');
        res.json(successResponse(userWithoutPassword));

    } catch (error) {
        req.log.error({ err: error }, 'Profile error');
        res.status(500).json(
            errorResponse('INTERNAL_ERROR', 'Internal server error')
        );
    }
});

// Update profile (защищенный)
app.put('/v1/users/me', authenticateToken, async (req, res) => {
    try {
        req.log.debug({ userId: req.user.userId, body: req.body }, 'Profile update attempt');

        const { error, value } = updateProfileSchema.validate(req.body);
        if (error) {
            req.log.warn({ error: error.details }, 'Profile update validation failed');
            return res.status(400).json(
                errorResponse(
                    'VALIDATION_ERROR',
                    'Validation failed',
                    error.details.map(d => d.message)
                )
            );
        }

        const userIndex = users.findIndex(user => user.id === req.user.userId);
        if (userIndex === -1) {
            req.log.warn({ userId: req.user.userId }, 'User not found for update');
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

        req.log.info({ userId: req.user.userId }, 'Profile updated successfully');

        res.json(
            successResponse({
                message: 'Profile updated successfully',
                user: updatedUser
            })
        );

    } catch (error) {
        req.log.error({ err: error }, 'Profile update error');
        res.status(500).json(
            errorResponse('INTERNAL_ERROR', 'Internal server error')
        );
    }
});

// List users (admin only) 
app.get('/v1/users', authenticateToken, requireAdmin, (req, res) => {
    try {
        req.log.debug({ adminId: req.user.userId }, 'Admin listing users');

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

        req.log.debug({ 
            adminId: req.user.userId, 
            count: usersWithoutPasswords.length 
        }, 'Users list retrieved');

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
        req.log.error({ err: error }, 'Users list error');
        res.status(500).json(
            errorResponse('INTERNAL_ERROR', 'Internal server error')
        );
    }
});

// Get user by ID (для внутреннего использования)
app.get('/v1/users/:userId', (req, res) => {
    try {
        const userId = req.params.userId;
        
        // Разрешаем доступ только для внутренних запросов или аутентифицированных пользователей
        if (!req.isInternalRequest && (!req.user || (req.user.userId !== userId && !req.user.roles.includes('admin')))) {
            return res.status(403).json(
                errorResponse('FORBIDDEN', 'Access denied')
            );
        }

        const user = users.find(u => u.id === userId);
        if (!user) {
            return res.status(404).json(
                errorResponse('USER_NOT_FOUND', 'User not found')
            );
        }

        // Для внутренних запросов возвращаем полную информацию
        const userData = req.isInternalRequest ? user : {
            id: user.id,
            email: user.email,
            name: user.name,
            roles: user.roles,
            createdAt: user.createdAt,
            updatedAt: user.updatedAt
        };

        res.json(successResponse({ user: userData }));

    } catch (error) {
        req.log.error({ err: error }, 'Get user error');
        res.status(500).json(
            errorResponse('INTERNAL_ERROR', 'Internal server error')
        );
    }
});

// Health check (публичный)
app.get('/health', (req, res) => {
    req.log.debug('Health check requested');
    res.json(
        successResponse({
            status: 'OK',
            service: 'Users Service',
            timestamp: new Date().toISOString(),
            userCount: users.length
        })
    );
});

app.get('/status', (req, res) => {
    res.json(successResponse({ status: 'Users service is running' }));
});

// 404 handler
app.use('*', (req, res) => {
    req.log.warn({ path: req.path }, 'Route not found');
    res.status(404).json(
        errorResponse('ROUTE_NOT_FOUND', 'Route not found')
    );
});

// Error handling middleware
app.use((err, req, res, next) => {
    req.log.error({ err: err }, 'Unhandled error');
    res.status(500).json(
        errorResponse('INTERNAL_ERROR', 'Internal server error')
    );
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
        logger.info('Test admin created: admin@test.com / admin123');
    }
};

// Start server
app.listen(PORT, '0.0.0.0', async () => {
    await createTestAdmin();
    logger.info({ port: PORT }, 'Users service started');
});