// Import required modules
const express = require('express');
const path = require('path');
const dotenv = require('dotenv')
//load environment variables
dotenv.config();

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;

// Set view engine to EJS
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
// Serve static files
app.use(express.static(path.join(__dirname, 'public')));
// Import routes
const indexRoutes = require('./routes/index');
app.use('/', indexRoutes);
// Start server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});