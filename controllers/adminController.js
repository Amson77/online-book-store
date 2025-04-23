const db = require("../config/db");


// Render admin dashboard with form and book list
const renderDashboard = async (req, res) => {
    try {
        const books = await db.any("SELECT * FROM books");
        const user = req.session.user;
        res.render("adminDashboard", { user, books });
    } catch (err) {
        res.status(500).send("Error loading admin dashboard");
    }
};


// Handle book addition
const addBook = async (req, res) => {
    const { title, author, price } = req.body;
    try {
        await db.none("INSERT INTO books (title, author, price) VALUES ($1, $2, $3)", [
            title,
            author,
            price,
        ]);
        res.redirect("/admin/dashboard");
    } catch (err) {
        console.error("❌ Error adding book:", err);
        res.status(500).send("Failed to add book");
    }
};


module.exports = { renderDashboard, addBook };


