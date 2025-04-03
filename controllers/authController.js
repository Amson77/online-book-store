const bcrypt = require('bcryptjs');
const db = require('../config/db');

// Register User
exports.registerUser = async (req, res) => {
    const { name, email, password } = req.body;
    
    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    try {
        // Insert new user into database
        await db.none('INSERT INTO users (name, email, password) VALUES ($1, $2, $3)', 
                      [name, email, hashedPassword]);
        res.status(201).json({ message: 'User registered successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error registering user' });
    }
};

// Login User
exports.loginUser = async (req, res) => {
    const { email, password } = req.body;

    try {
        // Check if user exists
        const user = await db.oneOrNone('SELECT * FROM users WHERE email = $1', [email]);

        if (!user) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        // Compare password with hashed password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        // Store user info in session
        req.session.user = { id: user.id, name: user.name, email: user.email };
        
        // Redirect to home page after successful login
        res.redirect('/home');
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error logging in' });
    }
};

// Logout User
exports.logoutUser = (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ error: 'Error logging out' });
        }
        res.json({ message: 'Logged out successfully' });
    });
};
