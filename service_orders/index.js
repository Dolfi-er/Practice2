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

app.get('/orders/:orderId', (req, res) => {
    const orderId = parseInt(req.params.orderId);
    const order = orders[orderId];

    if (!order) {
        return res.status(404).json({error: 'Order not found'});
    }

    res.json(order);
});

app.get('/orders', (req, res) => {
    let orders = Object.values(orders);

    // Добавляем фильтрацию по userId если передан параметр
    if (req.query.userId) {
        const userId = parseInt(req.query.userId);
        orders = orders.filter(order => order.userId === userId);
    }

    res.json(orders);
});

app.post('/orders', (req, res) => {
    const orderData = req.body;
    const orderId = currentId++;

    const newOrder = {
        id: orderId,
        ...orderData
    };

    orders[orderId] = newOrder;
    res.status(201).json(newOrder);
});

app.put('/orders/:orderId', (req, res) => {
    const orderId = parseInt(req.params.orderId);
    const orderData = req.body;

    if (!orders[orderId]) {
        return res.status(404).json({error: 'Order not found'});
    }

    orders[orderId] = {
        id: orderId,
        ...orderData
    };

    res.json(orders[orderId]);
});

app.delete('/orders/:orderId', (req, res) => {
    const orderId = parseInt(req.params.orderId);

    if (!orders[orderId]) {
        return res.status(404).json({error: 'Order not found'});
    }

    const deletedOrder = orders[orderId];
    delete orders[orderId];

    res.json({message: 'Order deleted', deletedOrder});
});

// Start server
app.listen(PORT, () => {
    console.log(`Orders service running on port ${PORT}`);
});