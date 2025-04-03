const db = require("../models/bookModel");


// Get all books from the database
const getBooks = async (req, res) => {
  try {
      const books = await db.any("SELECT * FROM books");
      // Pass user from session to the view
      const user = req.session.user;


      // Render books page with books and user data
      res.render("books", { books, user }); // Pass user here
  } catch (err) {
      console.error("❌ Error fetching books:", err);
      res.status(500).send("Internal Server Error");
  }
};


module.exports = { getBooks };


