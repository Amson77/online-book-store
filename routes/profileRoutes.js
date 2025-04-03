const express = require('express');
const router = express.Router();
const { isAuthenticated } = require('../config/authMiddleware');


// Profile route (only accessible by logged-in users)
router.get('/profile', isAuthenticated, (req, res) => {
    if (!req.session.user) {
        return res.redirect("/auth/login"); // Redirect if not logged in
    }

    res.render('profile', { user: req.session.user });
});


module.exports = router;
