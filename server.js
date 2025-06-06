const express = require('express');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();
const PORT = 3000;

// Secrets (in prod, load from env)
const ACCESS_TOKEN_SECRET = 'access-secret';
const REFRESH_TOKEN_SECRET = 'refresh-secret';

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// In-memory “DB”
const users = [
  { id: 1, username: 'piyush', password: '1234' }
];

// -----------------------------------------------------------------------------
// --- TOKEN CREATOR FUNCTIONS (THE MISSING PIECE) ---
// -----------------------------------------------------------------------------
function generateAccessToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username },
    ACCESS_TOKEN_SECRET,
    { expiresIn: '15s' }
  );
}
function generateRefreshToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username },
    REFRESH_TOKEN_SECRET,
    { expiresIn: '1d' }
  );
}
// -----------------------------------------------------------------------------

// ─── LOGIN ─────────────────────────────────────────────────────────────────────
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username && u.password === password);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  const accessToken = generateAccessToken(user);
  const refreshToken = generateRefreshToken(user);

  const cookieOptions = {
    httpOnly: true,
    secure: false, 
    sameSite: 'Strict',
    path: '/'
  };

  res.cookie('accessToken', accessToken, { ...cookieOptions, maxAge: 15 * 1000 });
  res.cookie('refreshToken', refreshToken, { ...cookieOptions, maxAge: 24 * 60 * 60 * 1000 });
  res.json({ message: 'Logged in successfully' });
});

// ─── PROTECTED ─────────────────────────────────────────────────────────────────
app.get('/protected', (req, res) => {
  console.log('Incoming cookies to /protected:', req.cookies); 
  const token = req.cookies.accessToken;
  if (!token) return res.status(401).json({ error: 'Access token missing' });

  try {
    const user = jwt.verify(token, ACCESS_TOKEN_SECRET);
    res.json({ message: '✅ Success! This is protected data!', user });
  } catch (err) {
    res.status(403).json({ error: 'Invalid or expired access token' });
  }
});

// ─── REFRESH ────────────────────────────────────────────────────────────────────
app.post('/refresh', (req, res) => {
  const token = req.cookies.refreshToken;
  if (!token) return res.status(401).json({ error: 'Refresh token missing' });

  try {
    const user = jwt.verify(token, REFRESH_TOKEN_SECRET);
    const newAccessToken = generateAccessToken(user);

    res.cookie('accessToken', newAccessToken, {
      httpOnly: true,
      secure: false,
      sameSite: 'Strict',
      path: '/',
      maxAge: 15 * 1000
    });
    res.json({ message: 'Access token refreshed' });
  } catch (err) {
    res.status(403).json({ error: 'Invalid or expired refresh token' });
  }
});

// ─── LOGOUT ─────────────────────────────────────────────────────────────────────
app.post('/logout', (req, res) => {
  const cookieOptions = { path: '/', sameSite: 'Strict' };
  res.clearCookie('accessToken', cookieOptions);
  res.clearCookie('refreshToken', cookieOptions);
  res.json({ message: 'Logged out successfully' });
});

// ─── START ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`🚀 Server running! Open http://localhost:${PORT} in your browser.`);
});