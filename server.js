const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const session = require('express-session');
const nodemailer = require('nodemailer');
const bcrypt = require('bcryptjs');
const crypto = require('crypto'); // For generating random strings
const bodyParser = require('body-parser'); // For parsing incoming request data
const jwt = require('jsonwebtoken'); // For JWT token generation

const app = express();
const encryptionKey = 'cRach5xun=t!+_6a2rutaPhe'; // Your encryption key

// MySQL connection
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'db_name',
});

// Middleware setup
app.use(bodyParser.json()); // to parse JSON bodies
app.use(cors({ origin: 'http://localhost:5173', methods: ['GET', 'POST'], credentials: true }));
app.use(session({
  secret: 'your_session_secret_key',
  resave: false,
  saveUninitialized: true,
  cookie: {
    secure: false, // Set to true in production with HTTPS
    httpOnly: true,
    maxAge: 3600000, // 1 hour session expiration
  },
}));

// Setup Nodemailer with Amazon SES
const transporter = nodemailer.createTransport({
  host: '',
  port: 587,
  secure: false, // Use TLS
  auth: {
    user: '', // Replace with your SES SMTP username
    pass: '', // Replace with your SES SMTP password
  },
});

// Generate a random string
function generateRandomString(length) {
  return crypto.randomBytes(length).toString('hex');
}

// Login Route
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: "Username and password are required" });
    }

    try {
        // Step 1: Check if the username exists in the 'users' table
        db.query(
            "SELECT userName, CAST(AES_DECRYPT(passWord, ?) AS CHAR) AS decryptedPassword, hccId, adminLevel FROM users WHERE userName = ?",
            [encryptionKey, username],
            (err, rows) => {
                if (err) {
                    console.error("Error during query:", err);
                    return res.status(500).json({ message: "Server error", error: err.message });
                }

                if (rows.length > 0) {
                    const user = rows[0];
                    console.log("Password from request (users table):", password);
                    console.log("Password from users table (decrypted):", user.decryptedPassword);

                    if (user.decryptedPassword === password) {
                        req.session.userId = user.hccId;
                        req.session.username = user.userName;
                        req.session.adminLevel = user.adminLevel;

                        const token = jwt.sign(
                            { userId: user.hccId, username: user.userName, adminLevel: user.adminLevel },
                            'your_jwt_secret',
                            { expiresIn: '1h' }
                        );

                        return res.json({
                            message: "Login successful",
                            token,
                            hccId: user.hccId,
                            adminLevel: user.adminLevel
                        });
                    } else {
                        // If password does not match in 'users' table, proceed to check in 'famusers' table
                        db.query(
                            "SELECT userName, CAST(AES_DECRYPT(passWord, ?) AS CHAR) AS decryptedPassword FROM famusers WHERE userName = ?",
                            [encryptionKey, username],
                            (errFamUser, famRows) => {
                                if (errFamUser) {
                                    console.error("Error during famusers query:", errFamUser);
                                    return res.status(500).json({ message: "Server error", error: errFamUser.message });
                                }

                                if (famRows.length > 0) {
                                    const famUser = famRows[0];
                                    console.log("Password from request (famusers table):", password);
                                    console.log("Password from famusers table (decrypted):", famUser.decryptedPassword);

                                    if (famUser.decryptedPassword === password) {
                                        req.session.userId = famUser.id;
                                        req.session.username = famUser.userName;

                                        const token = jwt.sign(
                                            { userId: famUser.id, username: famUser.userName },
                                            'your_jwt_secret',
                                            { expiresIn: '1h' }
                                        );

                                        return res.json({ message: "Login successful", token, isFamUser: true });
                                    } else {
                                        return res.status(401).json({ message: "Invalid credentials in famusers" });
                                    }
                                } else {
                                    return res.status(404).json({ message: "User not found in both users and famusers" });
                                }
                            }
                        );
                    }
                } else {
                    // Step 4: If user is not found in 'users' table, check the 'famusers' table directly
                    db.query(
                        "SELECT userName, CAST(AES_DECRYPT(passWord, ?) AS CHAR) AS decryptedPassword FROM famusers WHERE userName = ?",
                        [encryptionKey, username],
                        (errFamUser, famRows) => {
                            if (errFamUser) {
                                console.error("Error during famusers query:", errFamUser);
                                return res.status(500).json({ message: "Server error", error: errFamUser.message });
                            }

                            if (famRows.length > 0) {
                                const famUser = famRows[0];
                                console.log("Password from request (famusers table):", password);
                                console.log("Password from famusers table (decrypted):", famUser.decryptedPassword);

                                if (famUser.decryptedPassword === password) {
                                    req.session.userId = famUser.id;
                                    req.session.username = famUser.userName;

                                    const token = jwt.sign(
                                        { userId: famUser.id, username: famUser.userName },
                                        'your_jwt_secret',
                                        { expiresIn: '1h' }
                                    );

                                    return res.json({ message: "Login successful", token, isFamUser: true });
                                } else {
                                    return res.status(401).json({ message: "Invalid credentials in famusers" });
                                }
                            } else {
                                return res.status(404).json({ message: "User not found in both users and famusers" });
                            }
                        }
                    );
                }
            }
        );
    } catch (err) {
        console.error("Error during login:", err);
        res.status(500).json({ message: "Server error", error: err.message });
    }
});


// Forgot Password API
app.post('/forgot-password', (req, res) => {
    const { email } = req.body;
  
    if (!email) {
      return res.status(400).json({ message: 'Email is required' });
    }
  
    const checkUserTables = () => {
      return new Promise((resolve, reject) => {
        // Check in the 'users' table
        db.query('SELECT userName, userId FROM users WHERE email = ?', [email], (err, result) => {
          if (err) return reject({ message: 'Database error', error: err });
          if (result.length > 0) return resolve({ user: result[0], table: 'users' });
  
          // Check in the 'famusers' table
          db.query('SELECT a.userName, a.idfamUsers AS userId FROM famusers a INNER JOIN contact b on a.contactId=b.contactId WHERE emailAddress = ?', [email], (famErr, famResult) => {
            // db.query('SELECT famName AS userName, famId AS userId FROM famusers WHERE email = ?', [email], (famErr, famResult) => {
            if (famErr) return reject({ message: 'Database error', error: famErr });
            if (famResult.length > 0) return resolve({ user: famResult[0], table: 'famusers' });
  
            // If not found in either table
            resolve(null);
          });
        });
      });
    };
  
    checkUserTables()
      .then((userData) => {
        if (!userData) {
          return res.status(404).json({ message: 'No user found with the provided email' });
        }
  
        const { user, table } = userData;
        const resetToken = generateRandomString(16); // Generate a random token
        const expiresAt = new Date(Date.now() + 3600000); // Token expires in 1 hour
  
        // Save the reset token to the database
        db.query(
          'INSERT INTO password_reset_tokens (userId, token, expiresAt) VALUES (?, ?, ?)',
          [user.userId, resetToken, expiresAt],
          (insertErr) => {
            if (insertErr) {
              console.error('Error saving reset token:', insertErr);
              return res.status(500).json({ message: 'Error saving reset token', error: insertErr.message });
            }
  
            const resetLink = `http://localhost:5173/reset-password?token=${resetToken}`;
            const mailOptions = {
              from: 'abc@gmail.com',
              to: email,
              subject: 'Password Reset Request',
              html: `
                <p>Hi ${user.userName},</p>
                <p>You requested to reset your password. Please use the link below to reset your password:</p>
                <a href="${resetLink}" target="_blank">Reset Password</a>
                <p>This link will expire in 1 hour.</p>
                <p>If you did not request this, please ignore this email.</p>
                <p>Best Regards,<br>Zemplee Team</p>
              `,
            };
  
            // Send the email
            transporter.sendMail(mailOptions, (emailErr, info) => {
              if (emailErr) {
                console.error('Error sending email:', emailErr);
                return res.status(500).json({ message: 'Error sending email', error: emailErr.message });
              }
  
              res.json({ message: 'Password reset email sent successfully', info });
            });
          }
        );
      })
      .catch((error) => {
        console.error(error.message, error.error);
        res.status(500).json({ message: error.message, error: error.error?.message });
      });
  });
  
  
  // Reset Password API
  app.post('/reset-password', (req, res) => {
    const { token, newPassword } = req.body;
  
    if (!token || !newPassword) {
      return res.status(400).json({ message: 'Token and new password are required' });
    }
  
    // const encryptionKey = 'your_encryption_key'; // Ensure this key is non-empty and consistent
  
    // Check the reset token
    db.query(
      'SELECT userId FROM password_reset_tokens WHERE token = ? AND expiresAt > NOW()',
      [token],
      (err, result) => {
        if (err) {
          console.error('Error querying token:', err);
          return res.status(500).json({ message: 'Server error' });
        }
  
        if (result.length === 0) {
          return res.status(400).json({ message: 'Invalid or expired reset token' });
        }
  
        const userId = result[0].userId;
  
        // Log the new password and userId for debugging
        console.log('New password:', newPassword);
        console.log('User ID:', userId);
  
        // Update the user's password
        const encryptedPasswordQuery = `
          UPDATE users 
          SET passWord = AES_ENCRYPT(?, ?) 
          WHERE userId = ?
        `;
        db.query(
          encryptedPasswordQuery,
          [newPassword, encryptionKey, userId],
          (updateErr, updateResult) => {
            if (updateErr) {
              console.error('Error updating password:', updateErr);
              return res.status(500).json({ message: 'Error updating password' });
            }
  
            console.log('Password update result:', updateResult);
  
            // Clean up the reset token
            db.query(
              'DELETE FROM password_reset_tokens WHERE token = ?',
              [token],
              (deleteErr) => {
                if (deleteErr) {
                  console.error('Error deleting token:', deleteErr);
                  return res.status(500).json({ message: 'Error cleaning up token' });
                }
  
                res.json({ message: 'Password successfully reset' });
              }
            );
          }
        );
      }
    );
  });


  app.post("/forgot-username", (req, res) => {
    const { email } = req.body;
  
    if (!email) {
      return res.status(400).json({ message: "Email is required" });
    }
  
    // Check if the email exists in the database
    db.query(
      "SELECT userName FROM users WHERE email = ?",
      [email],
      (err, result) => {
        if (err) {
          console.error("Error querying the database:", err);
          return res.status(500).json({ message: "Server error" });
        }
  
        if (result.length === 0) {
          return res.status(404).json({ message: "No account found with this email" });
        }
  
        const userName = result[0].userName;
  
        // Send the username via email
        const mailOptions = {
          from: "abc@gmail.com",
          to: email,
          subject: "Your Username",
          text: `Hello, your username is: ${userName}`,
        };
  
        transporter.sendMail(mailOptions, (emailErr, info) => {
          if (emailErr) {
            console.error("Error sending email:", emailErr);
            return res.status(500).json({ message: "Error sending email" });
          }
  
          console.log("Email sent:", info.response);
          res.json({ message: "Username sent to your email address" });
        });
      }
    );
  });

// Start the server
const PORT = 4000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
