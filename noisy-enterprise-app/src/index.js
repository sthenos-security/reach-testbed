/**
 * Noisy Enterprise App - Main Entry Point
 * 
 * DEMO PURPOSE: This app has 95+ dependencies in package.json
 * but only imports ~15 of them. The rest are:
 * - Transitive dependencies
 * - Unused features
 * - Dev-only tools
 * 
 * REACHABLE will show that most CVEs in this app are NOT exploitable.
 */

'use strict';

// Core framework - REACHABLE
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');

// Data processing - REACHABLE
const _ = require('lodash');
const axios = require('axios');
const validator = require('validator');

// Auth - REACHABLE
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

// Database - REACHABLE
const mongoose = require('mongoose');

// Config - REACHABLE
require('dotenv').config();

// NOT IMPORTED (but in package.json):
// - moment, dayjs, date-fns, luxon (date libs - not used)
// - sharp, jimp, imagemin (image processing - not used)
// - puppeteer, playwright (browser automation - not used)
// - aws-sdk, googleapis (cloud SDKs - not used)
// - stripe, twilio (payment/sms - not used)
// - graphql, apollo-server (GraphQL - not used)
// - typeorm, sequelize (ORMs - using mongoose instead)
// - redis, bull, agenda (job queues - not used)
// - ... and 50+ more

const app = express();

// Middleware
app.use(helmet());
app.use(cors());
app.use(compression());
app.use(morgan('combined'));
app.use(express.json());

// Simple user schema
const UserSchema = new mongoose.Schema({
    email: String,
    password: String,
    name: String
});
const User = mongoose.model('User', UserSchema);

// Routes
app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.post('/api/register', async (req, res) => {
    try {
        const { email, password, name } = req.body;
        
        // Validate - uses validator (REACHABLE)
        if (!validator.isEmail(email)) {
            return res.status(400).json({ error: 'Invalid email' });
        }
        
        // Hash password - uses bcrypt (REACHABLE)
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Create user - uses mongoose (REACHABLE)
        const user = new User({ email, password: hashedPassword, name });
        await user.save();
        
        res.json({ success: true, userId: user._id });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        // Find user - uses mongoose (REACHABLE)
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // Check password - uses bcrypt (REACHABLE)
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // Generate token - uses jsonwebtoken (REACHABLE)
        const token = jwt.sign(
            { userId: user._id, email: user.email },
            process.env.JWT_SECRET || 'insecure-secret',
            { expiresIn: '24h' }
        );
        
        res.json({ token });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/users', async (req, res) => {
    try {
        // Uses lodash (REACHABLE)
        const users = await User.find().lean();
        const sanitized = _.map(users, u => _.pick(u, ['_id', 'email', 'name']));
        res.json(sanitized);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/external', async (req, res) => {
    try {
        // Uses axios (REACHABLE)
        const response = await axios.get('https://api.github.com/zen');
        res.json({ wisdom: response.data });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log('');
    console.log('=== REACHABLE DEMO ===');
    console.log('This app has 95+ dependencies but only uses ~15');
    console.log('Run REACHABLE to see the noise reduction!');
});

module.exports = app;
