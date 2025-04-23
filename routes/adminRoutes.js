const express = require("express");
const router = express.Router();
const { renderDashboard, addBook } = require("../controllers/adminController");
const { isAuthenticated } = require("../config/authMiddleware");
const { isAdmin } = require("../middleware/adminMiddleware");


router.get("/admin/dashboard", isAuthenticated, isAdmin, renderDashboard);
router.post("/admin/add-book", isAuthenticated, isAdmin, addBook);


module.exports = router;
