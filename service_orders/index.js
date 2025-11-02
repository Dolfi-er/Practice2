const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const Joi = require('joi');
const axios = require('axios');


const app = express();
const PORT = process.env.PORT || 8000;
const JWT_SECRET = process.env.JWT_SECRET || 'secret-key';
const USERS_SERVICE_URL = process.env.USERS_SERVICE_URL || 'http://service_users:8000';


// Middleware
app.use(cors());
app.use(express.json());


// Имитация базы данных в памяти (LocalStorage)
let orders = [];
let currentId = 1;


// Статусы заказов
const ORDER_STATUS = {
    CREATED: 'created',
    IN_PROGRESS: 'in_progress',
    COMPLETED: 'completed',
    CANCELLED: 'cancelled'
};


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

// Rights middleware
const checkOrderOwnership = (req, res, next) => {
    const orderId = req.params.orderId;
    const order = orders.find(o => o.id === orderId);

    if (!order) {
        return res.status(404).json({ error: 'Order not found' });
    }

    // Админы могут управлять любыми заказами
    if (req.user.roles.includes('admin')) {
        req.order = order;
        return next();
    }

    // Пользователи могут управлять только своими заказами
    if (order.userId !== req.user.userId) {
        return res.status(403).json({ error: 'Access denied to this order' });
    }

    req.order = order;
    next();
};


//Utils
const calculateTotal = (items) => {
    return items.reduce((total, item) => total + (item.quantity * item.price), 0);
};

const checkUserExists = async (userId) => {
    try {
        const response = await axios.get(`${USERS_SERVICE_URL}/users/${userId}`);
        return response.data && !response.data.error;
    } catch (error) {
        console.error('Error checking user existence:', error.message);
        return false;
    }
};


// Routes

// New order
app.post('/orders', authenticateToken, async (req, res) => {
    try {
        // Data validation
        const { error, value } = createOrderSchema.validate(req.body);
        if (error) {
            return res.status(400).json({
                error: 'Validation failed',
                details: error.details.map(d => d.message)
            });
        }

        const { items } = value;

        // User existence check
        const userExists = await checkUserExists(req.user.userId);
        if (!userExists) {
            return res.status(400).json({ error: 'User does not exist' });
        }

        // Total calculation
        const total = calculateTotal(items);

        // Order creation
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

        res.status(201).json({
            success: true,
            message: 'Order created successfully',
            order
        });

    } catch (error) {
        console.error('Order creation error:', error);
        res.status(500).json({
            error: 'Internal server error during order creation'
        });
    }
});

// Get order by ID
app.get('/orders/:orderId', authenticateToken, checkOrderOwnership, (req, res) => {
    try {
        res.json({
            success: true,
            order: req.order
        });
    } catch (error) {
        console.error('Get order error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Current user orders list with pagination and sorting
app.get('/orders', authenticateToken, (req, res) => {
    try {
        // Pag and sort params
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const sortBy = req.query.sortBy || 'createdAt';
        const sortOrder = req.query.sortOrder === 'asc' ? 1 : -1;
        const statusFilter = req.query.status;

        // Filter
        let userOrders = orders.filter(order => {
            // Admins see all orders, users - only their
            if (req.user.roles.includes('admin')) {
                return true;
            }
            return order.userId === req.user.userId;
        });

        // Status filter
        if (statusFilter && Object.values(ORDER_STATUS).includes(statusFilter)) {
            userOrders = userOrders.filter(order => order.status === statusFilter);
        }

        // Sort
        userOrders.sort((a, b) => {
            if (a[sortBy] < b[sortBy]) return -1 * sortOrder;
            if (a[sortBy] > b[sortBy]) return 1 * sortOrder;
            return 0;
        });

        // Pagination
        const startIndex = (page - 1) * limit;
        const endIndex = page * limit;

        const paginatedOrders = userOrders.slice(startIndex, endIndex);

        res.json({
            success: true,
            orders: paginatedOrders,
            pagination: {
                page,
                limit,
                total: userOrders.length,
                totalPages: Math.ceil(userOrders.length / limit),
                hasNext: endIndex < userOrders.length,
                hasPrev: page > 1
            },
            filters: {
                status: statusFilter,
                sortBy,
                sortOrder: sortOrder === 1 ? 'asc' : 'desc'
            }
        });

    } catch (error) {
        console.error('Orders list error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Update order status
app.put('/orders/:orderId/status', authenticateToken, checkOrderOwnership, (req, res) => {
    try {
        // Data validation
        const { error, value } = updateOrderStatusSchema.validate(req.body);
        if (error) {
            return res.status(400).json({
                error: 'Validation failed',
                details: error.details.map(d => d.message)
            });
        }

        const { status } = value;
        const order = req.order;

        // Check status transition
        const allowedStatusTransitions = {
            [ORDER_STATUS.CREATED]: [ORDER_STATUS.IN_PROGRESS, ORDER_STATUS.CANCELLED],
            [ORDER_STATUS.IN_PROGRESS]: [ORDER_STATUS.COMPLETED, ORDER_STATUS.CANCELLED],
            [ORDER_STATUS.COMPLETED]: [],
            [ORDER_STATUS.CANCELLED]: []
        };

        if (!allowedStatusTransitions[order.status].includes(status)) {
            return res.status(400).json({
                error: 'Invalid status transition',
                message: `Cannot change status from ${order.status} to ${status}`
            });
        }

        // Status update
        order.status = status;
        order.updatedAt = new Date().toISOString();

        res.json({
            success: true,
            message: 'Order status updated successfully',
            order
        });

    } catch (error) {
        console.error('Order status update error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Cancel order
app.put('/orders/:orderId/cancel', authenticateToken, checkOrderOwnership, (req, res) => {
    try {
        const order = req.order;

        // Posibility check
        if (order.status === ORDER_STATUS.COMPLETED) {
            return res.status(400).json({
                error: 'Cannot cancel completed order'
            });
        }

        if (order.status === ORDER_STATUS.CANCELLED) {
            return res.status(400).json({
                error: 'Order is already cancelled'
            });
        }

        // Cancellation
        order.status = ORDER_STATUS.CANCELLED;
        order.updatedAt = new Date().toISOString();

        res.json({
            success: true,
            message: 'Order cancelled successfully',
            order
        });

    } catch (error) {
        console.error('Order cancellation error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

//Get order by ID for gateway
app.get('/orders/:orderId', (req, res) => {
    const order = orders.find(order => order.id === req.params.orderId);
    if (!order) {
        return res.status(404).json({ error: 'Order not found' });
    }
    res.json(order);
});

app.get('/orders/status', (req, res) => {
    res.json({status: 'Orders service is running'});
});

app.get('/orders/health', (req, res) => {
    res.json({
        status: 'OK',
        service: 'Orders Service',
        timestamp: new Date().toISOString()
    });
});


// Start server
app.listen(PORT, () => {
    console.log(`Orders service running on port ${PORT}`);
});