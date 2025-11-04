const express = require('express');
const cors = require('cors');
const axios = require('axios');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 8000;

// Service URLs
const USERS_SERVICE_URL = process.env.USERS_SERVICE_URL || 'http://localhost:8001';
const ORDERS_SERVICE_URL = process.env.ORDERS_SERVICE_URL || 'http://localhost:8002';
const JWT_SECRET = process.env.JWT_SECRET || 'secret-key';

// Middleware
app.use(cors());
app.use(express.json());

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: JSON.stringify({
        success: false,
        error: {
            code: 'RATE_LIMIT_EXCEEDED',
            message: 'Too many requests from this IP'
        }
    })
});
app.use(limiter);

// Request ID middleware
app.use((req, res, next) => {
    req.requestId = req.headers['x-request-id'] || uuidv4();
    res.setHeader('X-Request-ID', req.requestId);
    next();
});

// Auth middleware
const authenticateToken = (req, res, next) => {
    // Публичные пути - пропускаем без аутентификации
    const publicPaths = [
        '/v1/users/register',
        '/v1/users/login',
        '/health',
        '/status'
    ];
    
    if (publicPaths.some(path => req.path.startsWith(path))) {
        return next();
    }

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

// Apply authentication to all routes
app.use(authenticateToken);

// Proxy request helper
const proxyRequest = async (serviceUrl, req, res) => {
    try {
        const headers = {
            'X-Request-ID': req.requestId,
            'Content-Type': 'application/json'
        };

        if (req.headers['authorization']) {
            headers['Authorization'] = req.headers['authorization'];
        }

        const response = await axios({
            method: req.method,
            url: `${serviceUrl}${req.path}`,
            data: req.body,
            headers: headers,
            params: req.query,
            validateStatus: (status) => status < 500
        });

        res.status(response.status).json(response.data);
    } catch (error) {
        console.error(`Proxy error to ${serviceUrl}:`, error.message);
        
        if (error.response) {
            res.status(error.response.status).json(error.response.data);
        } else if (error.request) {
            res.status(503).json({
                success: false,
                error: {
                    code: 'SERVICE_UNAVAILABLE',
                    message: 'Service temporarily unavailable'
                }
            });
        } else {
            res.status(500).json({
                success: false,
                error: {
                    code: 'GATEWAY_ERROR',
                    message: 'Internal gateway error'
                }
            });
        }
    }
};

// Public routes (без аутентификации)
app.post('/v1/users/register', (req, res) => proxyRequest(USERS_SERVICE_URL, req, res));
app.post('/v1/users/login', (req, res) => proxyRequest(USERS_SERVICE_URL, req, res));

// Health checks (публичные)
app.get('/health', (req, res) => {
    res.json({
        success: true,
        data: {
            status: 'OK',
            service: 'API Gateway',
            timestamp: new Date().toISOString()
        }
    });
});

app.get('/status', (req, res) => {
    res.json({
        success: true,
        data: { status: 'API Gateway is running' }
    });
});

// Users service routes (защищенные)
app.all('/v1/users*', (req, res) => proxyRequest(USERS_SERVICE_URL, req, res));

// Orders service routes (защищенные)  
app.all('/v1/orders*', (req, res) => proxyRequest(ORDERS_SERVICE_URL, req, res));

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({
        success: false,
        error: {
            code: 'ROUTE_NOT_FOUND',
            message: 'Route not found'
        }
    });
});

// Start server
app.listen(PORT, () => {
    console.log(`API Gateway running on port ${PORT}`);
});