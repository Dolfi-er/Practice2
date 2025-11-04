const express = require('express');
const cors = require('cors');
const axios = require('axios');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');
const jwt = require('jsonwebtoken');
const pino = require('pino');
const pinoHttp = require('pino-http');

const app = express();
const PORT = process.env.PORT || 8000;

// Service URLs
const USERS_SERVICE_URL = process.env.USERS_SERVICE_URL || 'http://localhost:8001';
const ORDERS_SERVICE_URL = process.env.ORDERS_SERVICE_URL || 'http://localhost:8002';
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
        service: 'api-gateway'
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
  },
  serializers: {
    req: (req) => ({
      id: req.id,
      method: req.method,
      url: req.url,
      headers: {
        'user-agent': req.headers['user-agent'],
        'content-type': req.headers['content-type']
      }
    }),
    res: (res) => ({
      statusCode: res.statusCode
    })
  }
});

// Middleware
app.use(cors());
app.use(express.json());
app.use(httpLogger);

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  handler: (req, res) => {
    logger.warn({ req: req }, 'Rate limit exceeded');
    res.status(429).json({
      success: false,
      error: {
        code: 'RATE_LIMIT_EXCEEDED',
        message: 'Too many requests from this IP'
      }
    });
  }
});
app.use(limiter);

// Request ID middleware (теперь интегрировано в pino-http)
app.use((req, res, next) => {
  req.requestId = req.id;
  res.setHeader('X-Request-ID', req.id);
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
    logger.warn({ req: req }, 'Authentication failed: missing token');
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
      logger.warn({ req: req, err: err.message }, 'Authentication failed: invalid token');
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

// Apply authentication to all routes
app.use(authenticateToken);

// Proxy request helper
const proxyRequest = async (serviceUrl, req, res) => {
  const startTime = Date.now();
  const serviceName = serviceUrl.includes('users') ? 'users-service' : 'orders-service';
  
  try {
    const headers = {
      'X-Request-ID': req.id,
      'Content-Type': 'application/json'
    };

    if (req.headers['authorization']) {
      headers['Authorization'] = req.headers['authorization'];
    }

    req.log.debug({ 
      service: serviceName,
      url: `${serviceUrl}${req.path}`,
      method: req.method 
    }, 'Proxying request to service');

    const response = await axios({
      method: req.method,
      url: `${serviceUrl}${req.path}`,
      data: req.body,
      headers: headers,
      params: req.query,
      validateStatus: (status) => status < 500
    });

    const duration = Date.now() - startTime;
    req.log.info({ 
      service: serviceName,
      status: response.status,
      duration: duration 
    }, 'Service response received');

    res.status(response.status).json(response.data);

  } catch (error) {
    const duration = Date.now() - startTime;
    
    if (error.response) {
      req.log.warn({ 
        service: serviceName,
        status: error.response.status,
        duration: duration,
        error: error.response.data 
      }, 'Service responded with error');
      res.status(error.response.status).json(error.response.data);
    } else if (error.request) {
      req.log.error({ 
        service: serviceName,
        duration: duration,
        error: error.message 
      }, 'Service unavailable');
      res.status(503).json({
        success: false,
        error: {
          code: 'SERVICE_UNAVAILABLE',
          message: 'Service temporarily unavailable'
        }
      });
    } else {
      req.log.error({ 
        service: serviceName,
        duration: duration,
        error: error.message 
      }, 'Gateway error');
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
  req.log.debug('Health check requested');
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
  req.log.warn({ path: req.path }, 'Route not found');
  res.status(404).json({
    success: false,
    error: {
      code: 'ROUTE_NOT_FOUND',
      message: 'Route not found'
    }
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  req.log.error({ err: err }, 'Unhandled error');
  res.status(500).json({
    success: false,
    error: {
      code: 'INTERNAL_ERROR',
      message: 'Internal server error'
    }
  });
});

// Start server
app.listen(PORT, () => {
  logger.info({ port: PORT }, 'API Gateway started');
});