
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Joi = require('joi');
const dotenv = require('dotenv');
const path = require('path');

dotenv.config();
const app = express();

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public'))); // Serve static files from 'public'

// Connect to MongoDB
mongoose.connect('mongodb+srv://vap:vap@vap.bxivt.mongodb.net/vap', {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log("Connected to MongoDB"))
  .catch(err => console.log("Failed to connect to MongoDB", err));

// User schema and model
const userSchema = new mongoose.Schema({
    username: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    rent: { type: Number, default: 0 },
    apartment: {
        type: apartmentSchema,  // Embed the apartment schema here
        default: null
    }
});

const User = mongoose.model('User', userSchema);

const apartmentSchema = new mongoose.Schema({
    apartmentNumber: { type: String, required: true },
    buildingName: { type: String, required: true },
    floor: { type: Number, required: true },
    rentDueDate: { type: Date, required: true }
}, { _id: false });


// Payment schema and model
const paymentSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    amount: { type: Number, required: true },
    method: { type: String, required: true },
    status: { type: String, default: 'Pending' }, // Could be 'Pending', 'Approved', etc.
    createdAt: { type: Date, default: Date.now }
});

const Payment = mongoose.model('Payment', paymentSchema);

// Maintenance Request schema and model
const maintenanceRequestSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    description: { type: String, required: true },
    status: { type: String, default: 'Pending' }, // Could be 'Pending', 'In Progress', 'Completed'
    createdAt: { type: Date, default: Date.now }
});

const MaintenanceRequest = mongoose.model('MaintenanceRequest', maintenanceRequestSchema);

// Validation schema using Joi
const registerSchema = Joi.object({
    username: Joi.string().min(3).required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(6).required()
});

// Register endpoint
app.post('/register', async (req, res) => {
    const { error } = registerSchema.validate(req.body);
    if (error) return res.status(400).json({ message: error.details[0].message });

    const userExists = await User.findOne({ email: req.body.email });
    if (userExists) return res.status(400).json({ message: 'User already exists' });

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(req.body.password, salt);

    const user = new User({
        username: req.body.username,
        email: req.body.email,
        password: hashedPassword
    });

    try {
        await user.save();
        const token = jwt.sign({ _id: user._id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.status(201).json({ message: 'User registered successfully', token });
    } catch (err) {
        res.status(500).json({ message: 'Something went wrong', error: err.message });
    }
});

// Login endpoint
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'Invalid email or password' });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(400).json({ message: 'Invalid email or password' });

    const token = jwt.sign({ _id: user._id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
    const refreshToken = jwt.sign({ _id: user._id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '30d' });
    user.refreshToken = refreshToken;
    await user.save();
    res.json({ message: 'Logged in successfully', token });
});


app.post('/token/refresh', async (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.sendStatus(401);

    try {
        const verified = jwt.verify(refreshToken, process.env.JWT_SECRET);
        const user = await User.findById(verified._id);
        if (!user || user.refreshToken !== refreshToken) return res.sendStatus(403);

        const token = jwt.sign({ _id: user._id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } catch (err) {
        res.sendStatus(403);
    }
});

// Middleware to verify token
const verifyToken = (req, res, next) => {
    const token = req.header('Authorization');
    if (!token) return res.status(401).json({ message: 'Access denied. No token provided.' });

    try {
        const verified = jwt.verify(token.split(" ")[1], process.env.JWT_SECRET);
        req.user = verified;
        next();
    } catch (err) {
        res.status(400).json({ message: 'Invalid token' });
    }
};


// Get user data including rent amount
app.get('/api/user', verifyToken, async (req, res) => {
    try {
        const user = await User.findById(req.user._id).select('username rent apartment');
        if (!user) return res.status(404).json({ message: 'User not found' });

        res.json({
            username: user.username,
            rentAmount: user.rent,
            apartment: user.apartment
        });
    } catch (error) {
        res.status(500).json({ message: 'Error fetching user data', error: error.message });
    }
});


// Get user apartment details
app.get('/api/user/apartment', verifyToken, async (req, res) => {
    try {
        // Fetch user details based on authenticated token
        const user = await User.findById(req.user._id).select('username apartment');
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Check if the user has apartment details assigned
        if (!user.apartment) {
            return res.status(404).json({ message: 'No apartment assigned yet' });
        }

        // Send back apartment details
        res.json({
            username: user.username,
            apartment: user.apartment
        });
    } catch (error) {
        res.status(500).json({ message: 'Error fetching apartment details', error: error.message });
    }
});




// Fake payment processing endpoint
app.post('/api/payment', verifyToken, async (req, res) => {
    const { amount, method } = req.body;

    if (!amount || !method) {
        return res.status(400).json({ message: 'Amount and payment method are required' });
    }

    const payment = new Payment({
        userId: req.user._id,
        amount,
        method,
    });

    try {
        await payment.save();
        res.status(201).json({ message: 'Payment processed successfully', payment });
    } catch (err) {
        res.status(500).json({ message: 'Error processing payment', error: err.message });
    }
});


// Update payment status (for admin)
app.put('/api/payment/:id/status', async (req, res) => {
    const { status } = req.body;
    const allowedStatuses = ['Pending', 'Approved'];

    if (!allowedStatuses.includes(status)) {
        return res.status(400).json({ message: 'Status must be either "Pending" or "Approved"' });
    }

    try {
        const payment = await Payment.findByIdAndUpdate(req.params.id, { status }, { new: true });
        if (!payment) return res.status(404).json({ message: 'Payment not found' });

        res.json({ message: 'Payment status updated successfully', payment });
    } catch (err) {
        res.status(500).json({ message: 'Error updating payment status', error: err.message });
    }
});

// Get admin dashboard data
app.get('/api/admin/dashboard', async (req, res) => {
    try {
        const users = await User.find();
        const payments = await Payment.find().populate('userId', 'username email');
        const maintenanceRequests = await MaintenanceRequest.find().populate('userId', 'username email');

        const dashboardData = users.map(user => {
            return {
                user,
                payments: payments.filter(payment => payment.userId._id.equals(user._id)),
                maintenanceRequests: maintenanceRequests.filter(request => request.userId._id.equals(user._id)),
            };
        });
        console.log(dashboardData);
        res.json(dashboardData);
    } catch (err) {
        res.status(500).json({ message: 'Error fetching dashboard data', error: err.message });
    }
});

// Admin sets rent for a specific user
app.put('/api/admin/user/:id/rent', async (req, res) => {
    try {
        const { rent } = req.body;
        if (!rent || rent < 0) {
            return res.status(400).json({ message: 'Invalid rent amount' });
        }

        const user = await User.findByIdAndUpdate(req.params.id, { rent }, { new: true });
        if (!user) return res.status(404).json({ message: 'User not found' });

        res.json({ message: 'Rent amount updated successfully', user });
    } catch (err) {
        res.status(500).json({ message: 'Error updating rent amount', error: err.message });
    }
});


// Admin assigns apartment details to a specific user
app.put('/api/admin/user/:id/assign-apartment', async (req, res) => {
    try {
        const { apartmentDetails } = req.body;

        if (!apartmentDetails) {
            return res.status(400).json({ message: 'Apartment details are required' });
        }

        // Validate apartment details against the apartment schema
        const apartmentValidation = Joi.object({
            apartmentNumber: Joi.string().required(),
            buildingName: Joi.string().required(),
            floor: Joi.number().required(),
            rentDueDate: Joi.date().required()
        }).validate(apartmentDetails);

        if (apartmentValidation.error) {
            return res.status(400).json({ message: apartmentValidation.error.details[0].message });
        }

        const user = await User.findByIdAndUpdate(
            req.params.id,
            { apartment: apartmentDetails },
            { new: true }
        );

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.json({ message: 'Apartment assigned successfully', user });
    } catch (err) {
        res.status(500).json({ message: 'Error assigning apartment', error: err.message });
    }
});


// Maintenance Request endpoint
app.post('/api/maintenance', verifyToken, async (req, res) => {
    const { description } = req.body;

    if (!description) {
        return res.status(400).json({ message: 'Description is required' });
    }

    const request = new MaintenanceRequest({
        userId: req.user._id,
        description
    });

    try {
        await request.save();
        res.status(201).json({ message: 'Maintenance request submitted successfully', request });
    } catch (err) {
        res.status(500).json({ message: 'Error submitting maintenance request', error: err.message });
    }
});

// Get admin dashboard data
app.get('/api/admin/dashboard', verifyToken, async (req, res) => {
    try {
        const users = await User.find();
        const payments = await Payment.find().populate('userId', 'username email');
        const maintenanceRequests = await MaintenanceRequest.find().populate('userId', 'username email');

        const dashboardData = users.map(user => {
            return {
                user,
                payments: payments.filter(payment => payment.userId._id.equals(user._id)),
                maintenanceRequests: maintenanceRequests.filter(request => request.userId._id.equals(user._id)),
            };
        });
        console.log(dashboardData);
        res.json(dashboardData);
    } catch (err) {
        res.status(500).json({ message: 'Error fetching dashboard data', error: err.message });
    }
});

// Serve the admin dashboard HTML page
app.get('/admin/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin_dashboard.html'));
});

// Serve HTML pages
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'public', 'register.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
