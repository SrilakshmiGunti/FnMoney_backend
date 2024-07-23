const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const path = require('path');

const app = express();
const port = process.env.PORT || 5000;
const jwtSecret = process.env.JWT_SECRET || 'your_jwt_secret_key';

// Middleware
app.use(cors());
app.use(bodyParser.json());

// MySQL connection
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '1234567890',
  database: 'fnmoney'
});

db.connect(err => {
  if (err) {
    throw err;
  }
  console.log('MySQL connected...');
});

// Registration endpoint
app.post('/api/register', (req, res) => {
  const { username, email, password } = req.body;

  bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) {
      return res.status(500).send({ message: 'Error hashing password' });
    }

    const sql = 'INSERT INTO users (username, email, password) VALUES (?, ?, ?)';
    db.query(sql, [username, email, hashedPassword], (err, result) => {
      if (err) {
        return res.status(500).send(err);
      }
      res.status(200).send({ message: 'User registered' });
    });
  });
});

// Login endpoint
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  const sql = 'SELECT * FROM users WHERE email = ?';

  db.query(sql, [email], (err, results) => {
    if (err) {
      return res.status(500).send(err);
    }

    if (results.length > 0) {
      const user = results[0];
      bcrypt.compare(password, user.password, (err, isMatch) => {
        if (err) {
          return res.status(500).send({ message: 'Error comparing passwords' });
        }

        if (isMatch) {
          const token = jwt.sign({ userId: user.id }, jwtSecret, { expiresIn: '1h' });
          res.status(200).send({ message: 'Login successful', token });
        } else {
          res.status(401).send({ message: 'Invalid credentials' });
        }
      });
    } else {
      res.status(401).send({ message: 'Invalid credentials' });
    }
  });
});

// Middleware to authenticate JWT tokens
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) return res.status(401).send({ message: 'No token provided' });

  jwt.verify(token, jwtSecret, (err, user) => {
    if (err) return res.status(403).send({ message: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Assessment submission endpoint (protected)
app.post('/api/assessments', authenticateToken, (req, res) => {
  const { assessmentName, score } = req.body;
  const sql = 'INSERT INTO assessments (assessmentName, score) VALUES (?, ?)';

  db.query(sql, [assessmentName, score], (err, result) => {
    if (err) {
      return res.status(500).send(err);
    }
    res.status(200).send({ message: 'Assessment submitted' });
  });
});

// Contact endpoint
app.post('/api/contact', (req, res) => {
  const { name, email, message } = req.body;
  const sql = 'INSERT INTO contacts (name, email, message) VALUES (?, ?, ?)';

  db.query(sql, [name, email, message], (err, result) => {
    if (err) {
      return res.status(500).send(err);
    }
    res.status(200).send({ message: 'Message received' });
  });
});

// Serve static files from the React frontend app
app.use(express.static(path.join(__dirname, 'client/build')));

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'client/build', 'index.html'));
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
