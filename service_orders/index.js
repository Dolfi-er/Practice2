const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const Joi = require('joi');
const axios = require('axios');
const pino = require('pino');
const pinoHttp = require('pino-http');

const app = express();
const PORT = process.env.PORT || 8002;
const JWT_SECRET = process.env.JWT_SECRET || 'secret-key';
const USERS_SERVICE_URL = process.env.USERS_SERVICE_URL || 'http://service_users:8001';

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
        service: 'orders-service'
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
let orders = [];

// Статусы заказов
const ORDER_STATUS = {
    CREATED: 'created',
    IN_PROGRESS: 'in_progress',
    COMPLETED: 'completed',
    CANCELLED: 'cancelled'
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

// Event Bus с логированием
class EventBus {
    async publish(eventType, eventData) {
        const event = {
            id: uuidv4(),
            type: eventType,
            timestamp: new Date().toISOString(),
            data: eventData,
            source: 'orders-service'
        };
        
        logger.info({ event: event }, 'Domain event published');
        return event;
    }
}

const eventBus = new EventBus();

// Schemas
const createOrderSchema = Joi.object({
    items: Joi.array().items(
        Joi.object({
            product: Joi.string().min(1).max(255).required(),
            quantity: Joi.number().integer().min(1).required(),
            price: Joi.number().precision(2).min(0).required()
        })
    ).min(1).required()
});

const updateOrderStatusSchema = Joi.object({
    status: Joi.string().valid(...Object.values(ORDER_STATUS)).required()
});

// Auth middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        req.log.warn('Authentication failed: missing token');
        return res.status(401).json(
            errorResponse('UNAUTHORIZED', 'Access token required')
        );
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            req.log.warn({ err: err.message }, 'Authentication failed: invalid token');
            return res.status(403).json(
                errorResponse('INVALID_TOKEN', 'Invalid or expired token')
            );
        }
        req.user = user;
        req.log.info({ userId: user.userId }, 'User authenticated');
        next();
    });
};

// Rights middleware
const checkOrderOwnership = (req, res, next) => {
    const orderId = req.params.orderId;
    const order = orders.find(o => o.id === orderId);

    if (!order) {
        req.log.warn({ orderId: orderId }, 'Order not found');
        return res.status(404).json(
            errorResponse('ORDER_NOT_FOUND', 'Order not found')
        );
    }

    if (req.user.roles.includes('admin')) {
        req.order = order;
        return next();
    }

    if (order.userId !== req.user.userId) {
        req.log.warn({ userId: req.user.userId, orderId: orderId }, 'Access denied to order');
        return res.status(403).json(
            errorResponse('FORBIDDEN', 'Access denied to this order')
        );
    }

    req.order = order;
    next();
};

//Utils
const calculateTotal = (items) => {
    return items.reduce((total, item) => total + (item.quantity * item.price), 0);
};

const checkUserExists = async (userId, req = null) => {
    try {
        if (req && req.log) {
            req.log.debug({ userId: userId }, 'Checking user existence');
        }
        
        // Используем внутренний endpoint для проверки пользователя
        const response = await axios.get(`${USERS_SERVICE_URL}/v1/users/${userId}`, {
            headers: {
                'Content-Type': 'application/json',
                // Добавляем внутренний токен или обходим аутентизацию для межсервисных вызовов
                'x-internal-request': 'true'
            },
            timeout: 5000
        });
        
        const exists = response.data && response.data.success && response.data.data && response.data.data.user;
        
        if (req && req.log) {
            if (!exists) {
                req.log.warn({ userId: userId }, 'User not found');
            } else {
                req.log.debug({ userId: userId }, 'User exists');
            }
        }
        
        return exists;
    } catch (error) {
        if (req && req.log) {
            req.log.error({ userId: userId, err: error.message }, 'Error checking user existence');
        } else {
            console.error('Error checking user existence:', error.message);
        }
        return false;
    }
};

// Routes

// New order (защищенный)
app.post('/v1/orders', authenticateToken, async (req, res) => {
    try {
        req.log.debug({ userId: req.user.userId, body: req.body }, 'Order creation attempt');

        const { error, value } = createOrderSchema.validate(req.body);
        if (error) {
            req.log.warn({ error: error.details }, 'Order validation failed');
            return res.status(400).json(
                errorResponse(
                    'VALIDATION_ERROR',
                    'Validation failed',
                    error.details.map(d => d.message)
                )
            );
        }

        const { items } = value;

        const userExists = await checkUserExists(req.user.userId, req);
        if (!userExists) {
            return res.status(400).json(
                errorResponse('USER_NOT_FOUND', 'User does not exist')
            );
        }

        const total = calculateTotal(items);

        const order = {
            id: uuidv4(),
            userId: req.user.userId,
            items: items.map(item => ({
                ...item,
                subtotal: item.quantity * item.price
            })),
            status: ORDER_STATUS.CREATED,
            total,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
        };

        orders.push(order);

        // Публикация события
        await eventBus.publish('ORDER_CREATED', {
            orderId: order.id,
            userId: order.userId,
            items: order.items,
            total: order.total,
            status: order.status
        });

        req.log.info({ 
            orderId: order.id, 
            userId: order.userId, 
            total: order.total 
        }, 'Order created successfully');

        res.status(201).json(
            successResponse({
                message: 'Order created successfully',
                order: order
            })
        );

    } catch (error) {
        req.log.error({ err: error }, 'Order creation error');
        res.status(500).json(
            errorResponse('INTERNAL_ERROR', 'Internal server error during order creation')
        );
    }
});

// Get order by ID (защищенный)
app.get('/v1/orders/:orderId', authenticateToken, checkOrderOwnership, (req, res) => {
    try {
        req.log.debug({ orderId: req.params.orderId }, 'Order retrieval');
        res.json(successResponse({ order: req.order }));
    } catch (error) {
        req.log.error({ err: error }, 'Get order error');
        res.status(500).json(
            errorResponse('INTERNAL_ERROR', 'Internal server error')
        );
    }
});

// Current user orders list (защищенный)
app.get('/v1/orders', authenticateToken, (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const sortBy = req.query.sortBy || 'createdAt';
        const sortOrder = req.query.sortOrder === 'asc' ? 1 : -1;
        const statusFilter = req.query.status;

        req.log.debug({ 
            userId: req.user.userId, 
            filters: { page, limit, statusFilter } 
        }, 'Orders list request');

        let userOrders = orders.filter(order => {
            if (req.user.roles.includes('admin')) return true;
            return order.userId === req.user.userId;
        });

        if (statusFilter && Object.values(ORDER_STATUS).includes(statusFilter)) {
            userOrders = userOrders.filter(order => order.status === statusFilter);
        }

        userOrders.sort((a, b) => {
            if (a[sortBy] < b[sortBy]) return -1 * sortOrder;
            if (a[sortBy] > b[sortBy]) return 1 * sortOrder;
            return 0;
        });

        const startIndex = (page - 1) * limit;
        const endIndex = page * limit;
        const paginatedOrders = userOrders.slice(startIndex, endIndex);

        req.log.debug({ 
            userId: req.user.userId, 
            count: paginatedOrders.length 
        }, 'Orders list retrieved');

        res.json(
            successResponse({
                orders: paginatedOrders,
                pagination: {
                    page,
                    limit,
                    total: userOrders.length,
                    totalPages: Math.ceil(userOrders.length / limit),
                    hasNext: endIndex < userOrders.length,
                    hasPrev: page > 1
                }
            })
        );

    } catch (error) {
        req.log.error({ err: error }, 'Orders list error');
        res.status(500).json(
            errorResponse('INTERNAL_ERROR', 'Internal server error')
        );
    }
});

// Update order status (защищенный)
app.put('/v1/orders/:orderId/status', authenticateToken, checkOrderOwnership, async (req, res) => {
    try {
        const { error, value } = updateOrderStatusSchema.validate(req.body);
        if (error) {
            req.log.warn({ error: error.details }, 'Status update validation failed');
            return res.status(400).json(
                errorResponse(
                    'VALIDATION_ERROR',
                    'Validation failed',
                    error.details.map(d => d.message)
                )
            );
        }

        const { status } = value;
        const order = req.order;
        const oldStatus = order.status;

        const allowedStatusTransitions = {
            [ORDER_STATUS.CREATED]: [ORDER_STATUS.IN_PROGRESS, ORDER_STATUS.CANCELLED],
            [ORDER_STATUS.IN_PROGRESS]: [ORDER_STATUS.COMPLETED, ORDER_STATUS.CANCELLED],
            [ORDER_STATUS.COMPLETED]: [],
            [ORDER_STATUS.CANCELLED]: []
        };

        if (!allowedStatusTransitions[order.status].includes(status)) {
            req.log.warn({ 
                orderId: order.id, 
                oldStatus: oldStatus, 
                newStatus: status 
            }, 'Invalid status transition');
            
            return res.status(400).json(
                errorResponse(
                    'INVALID_STATUS_TRANSITION',
                    `Cannot change status from ${order.status} to ${status}`
                )
            );
        }

        order.status = status;
        order.updatedAt = new Date().toISOString();

        await eventBus.publish('ORDER_STATUS_UPDATED', {
            orderId: order.id,
            userId: order.userId,
            oldStatus: oldStatus,
            newStatus: status
        });

        req.log.info({ 
            orderId: order.id, 
            oldStatus: oldStatus, 
            newStatus: status 
        }, 'Order status updated');

        res.json(
            successResponse({
                message: 'Order status updated successfully',
                order: order
            })
        );

    } catch (error) {
        req.log.error({ err: error }, 'Order status update error');
        res.status(500).json(
            errorResponse('INTERNAL_ERROR', 'Internal server error')
        );
    }
});

// Cancel order (защищенный)
app.put('/v1/orders/:orderId/cancel', authenticateToken, checkOrderOwnership, async (req, res) => {
    try {
        const order = req.order;

        if (order.status === ORDER_STATUS.COMPLETED) {
            req.log.warn({ orderId: order.id }, 'Cannot cancel completed order');
            return res.status(400).json(
                errorResponse('INVALID_OPERATION', 'Cannot cancel completed order')
            );
        }

        if (order.status === ORDER_STATUS.CANCELLED) {
            req.log.warn({ orderId: order.id }, 'Order already cancelled');
            return res.status(400).json(
                errorResponse('INVALID_OPERATION', 'Order is already cancelled')
            );
        }

        const oldStatus = order.status;
        order.status = ORDER_STATUS.CANCELLED;
        order.updatedAt = new Date().toISOString();

        await eventBus.publish('ORDER_CANCELLED', {
            orderId: order.id,
            userId: order.userId,
            oldStatus: oldStatus
        });

        req.log.info({ orderId: order.id }, 'Order cancelled');

        res.json(
            successResponse({
                message: 'Order cancelled successfully',
                order: order
            })
        );

    } catch (error) {
        req.log.error({ err: error }, 'Order cancellation error');
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
            service: 'Orders Service',
            timestamp: new Date().toISOString(),
            orderCount: orders.length
        })
    );
});

app.get('/status', (req, res) => {
    res.json(successResponse({ status: 'Orders service is running' }));
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

// Start server
app.listen(PORT, () => {
    logger.info({ port: PORT }, 'Orders service started');
});