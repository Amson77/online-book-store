// middleware/adminMiddleware.js
require('dotenv').config();


function isAdmin(req, res, next) {
    const adminEmail = process.env.ADMIN_EMAIL;
    if (req.session.user && req.session.user.email === adminEmail) {
        return next();
    }
    res.status(403).send("Access Denied: Admins Only");
}


module.exports = { isAdmin };
