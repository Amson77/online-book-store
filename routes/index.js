const express = require('express');
const router = express.Router();

// Render the landing page
router.get('/', (req, res) => { 
    res.render('index', { title: 'Online Book Store' });
});

module.exports = router;