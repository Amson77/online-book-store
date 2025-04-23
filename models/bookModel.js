const db = require("../config/db");

// Create Book table (if it doesn’t exist)
const createBookTable = async () => {
  const query = `
    CREATE TABLE IF NOT EXISTS books (
      id SERIAL PRIMARY KEY,
      title VARCHAR(255) NOT NULL,
      author VARCHAR(255) NOT NULL,
      price DECIMAL(10,2) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `;
  try {
    await db.none(query);
    console.log("✅ Book table is ready!");
  } catch (err) {
    console.error("❌ Error creating Book table:", err);
  }
};

// Ensure the table is created when the server starts
createBookTable();

module.exports = db;
