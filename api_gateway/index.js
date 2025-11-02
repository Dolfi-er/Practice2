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
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP'
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
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
};

// Proxy request helper
const proxyRequest = async (serviceUrl, req, res) => {
    try {
        const headers = {
            'X-Request-ID': req.requestId,
            'Content-Type': 'application/json'
        };

        // Forward auth header if present
        if (req.headers['authorization']) {
            headers['Authorization'] = req.headers['authorization'];
        }

        const response = await axios({
            method: req.method,
            url: `${serviceUrl}${req.originalUrl}`,
            data: req.body,
            headers: headers,
            validateStatus: (status) => status < 500 // Don't throw on 4xx errors
        });

        // Forward the response
        res.status(response.status).json(response.data);
    } catch (error) {
        console.error(`Proxy error to ${serviceUrl}:`, error.message);
        
        if (error.response) {
            // Service responded with error
            res.status(error.response.status).json(error.response.data);
        } else if (error.request) {
            // Service unavailable
            res.status(503).json({ error: 'Service temporarily unavailable' });
        } else {
            res.status(500).json({ error: 'Internal gateway error' });
        }
    }
};

// Public routes (no authentication required)
app.post('/users/register', (req, res) => proxyRequest(USERS_SERVICE_URL, req, res));
app.post('/users/login', (req, res) => proxyRequest(USERS_SERVICE_URL, req, res));

// Health checks (public)
app.get('/users/health', (req, res) => proxyRequest(USERS_SERVICE_URL, req, res));
app.get('/orders/health', (req, res) => proxyRequest(ORDERS_SERVICE_URL, req, res));
app.get('/status', (req, res) => {
    res.json({ status: 'API Gateway is running' });
});

// Protected routes - require authentication
app.use('/users', authenticateToken);
app.use('/orders', authenticateToken);

// Users service routes
app.all('/users*', (req, res) => proxyRequest(USERS_SERVICE_URL, req, res));

// Orders service routes  
app.all('/orders*', (req, res) => proxyRequest(ORDERS_SERVICE_URL, req, res));

// 404 handler for undefined routes
app.use('*', (req, res) => {
    res.status(404).json({ error: 'Route not found' });
});

// Start server
app.listen(PORT, () => {
    console.log(`API Gateway running on port ${PORT}`);
});