const express = require("express");
const db = require("../config/db");
const router = express.Router();

const encryptionKey = ""; // Encryption key for AES

// Register Endpoint
router.post("/register", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: "Username and password are required" });
  }

  try {
    // Check if the user already exists
    const [existingUser] = await db.promise().query(
      "SELECT * FROM users WHERE userName = ?",
      [username]
    );

    if (existingUser.length > 0) {
      return res.status(400).json({ message: "Username already exists" });
    }

    // Insert new user with AES_ENCRYPT
    await db.promise().query(
      "INSERT INTO users (userName, passWord) VALUES (?, AES_ENCRYPT(?, ?))",
      [username, password, encryptionKey]
    );

    res.status(201).json({ message: "User registered successfully" });
  } catch (err) {
    console.error("Error during registration:", err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

// Login Endpoint
router.post("/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: "Username and password are required" });
  }

  try {
    // Retrieve user and decrypt the password
    const [rows] = await db.promise().query(
      "SELECT userName, CAST(AES_DECRYPT(passWord, ?) AS CHAR) AS decryptedPassword, hccId FROM users WHERE userName = ?",
      [encryptionKey, username]
    );

    if (rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    const user = rows[0];

    // Compare decrypted password with provided password
    if (user.decryptedPassword !== password) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    // Send the hccId along with the login response
    res.json({ message: "Login successful", username: user.userName, hccId: user.hccId });
  } catch (err) {
    console.error("Error during login:", err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

module.exports = router;
