// Import required modules
const express = require('express');
const path = require('path');
const dotenv  =  require('dotenv')
const session = require('express-session');
const db = require('./config/db');
const bodyParser = require('body-parser');
const indexRoutes = require('./routes/index');
const authRoutes = require('./routes/authRoutes');
const homeRoutes = require('./routes/homeRoutes');
const profileRoutes = require('./routes/profileRoutes');


//load environment variables
dotenv.config();


// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;


app.use(bodyParser.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: 'gyeltshenMk',
    resave: false,
    saveUninitialized: true,
    cookie: {
        secure: false,
        maxAge: 60 * 60 * 1000 //session expries after 1 hour
    }
}));


// Set view engine to EJS
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));


// Serve static files
app.use(express.static(path.join(__dirname, 'public')));
app.use('/components', express.static(path.join(__dirname, 'views/components')));




// routes
app.use('/', indexRoutes);
app.use('/auth', authRoutes);
app.use('/', homeRoutes);
app.use('/', profileRoutes);


//for db connection
app.get('/db-test', async (req, res) => {
    try {
        const result = await db.one('SELECT NOW() AS current_time');
        res.json({ message: 'Database connected successfully', time: result.current_time });
    } catch (err) {
        res.status(500).json({ error: 'Database connection failed', details: err.message });
    }
});


// Start server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
