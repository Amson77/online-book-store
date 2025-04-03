// Middleware to check if user is authenticated
function isAuthenticated(req, res, next) {
    if (req.session.user && (req.session.cookie.expires > Date.now())) {
        return next(); // If session is valid, proceed to the next middleware/route handler
    }


    req.session.destroy(() => {
        res.redirect('/auth/login'); // Redirect to login if session expired or user not logged in
    });
}


module.exports = { isAuthenticated };
