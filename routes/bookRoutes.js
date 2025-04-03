const express = require("express");
const { getBooks } = require("../controllers/bookController");
const router = express.Router();


router.get("/books", getBooks); // Route to display books


module.exports = router;