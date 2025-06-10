import express from 'express';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import path from 'path';

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
// --- TOKEN CREATOR FUNCTIONS ---
// -----------------------------------------------------------------------------
function generateAccessToken(user) {
    const token = jwt.sign(
        { id: user.id, username: user.username },
        ACCESS_TOKEN_SECRET,
        { expiresIn: '15s' }
    );
    console.log(`Generated access token for ${user.username}`);
    return token;
}

function generateRefreshToken(user) {
    const token = jwt.sign(
        { id: user.id, username: user.username },
        REFRESH_TOKEN_SECRET,
        { expiresIn: '1d' }
    );
    console.log(`Generated refresh token for ${user.username}`);
    return token;
}

// Helper for structured responses
function sendResponse(res, status, message, data = null) {
    res.json({ status, message, data });
}

// ─── LOGIN ────────────────────────────────────────────────────────────────
app.post('/login', (req, res) => {
    console.log('Login attempt:', req.body);
    const { username, password } = req.body;
    const user = users.find(u => u.username === username && u.password === password);
    if (!user) {
        console.error('Invalid credentials for user:', username);
        return res.status(401).json({ 
            status: 'error', 
            message: 'Invalid credentials', 
            data: null 
        });
    }

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
    
    console.log(`User ${username} logged in successfully.`);
    sendResponse(res, 'success', 'Logged in successfully', { username });
});

// ─── PROTECTED ──────────────────────────────────────────────────────────────
app.get('/protected', (req, res) => {
    console.log('Accessing protected resource. Cookies:', req.cookies);
    const token = req.cookies.accessToken;
    if (!token) {
        console.error('Access token missing');
        return res.status(401).json({ 
            status: 'error', 
            message: 'Access token missing', 
            data: null 
        });
    }

    try {
        const user = jwt.verify(token, ACCESS_TOKEN_SECRET);
        console.log(`User ${user.username} accessed protected route.`);
        sendResponse(res, 'success', 'Protected data retrieved', { user });
    } catch (err) {
        console.error('Invalid or expired access token:', err.message);
        res.status(403).json({ 
            status: 'error', 
            message: 'Invalid or expired access token', 
            data: null 
        });
    }
});

// ─── REFRESH ────────────────────────────────────────────────────────────────
app.post('/refresh', (req, res) => {
    console.log('Token refresh attempt. Cookies:', req.cookies);
    const token = req.cookies.refreshToken;
    if (!token) {
        console.error('Refresh token missing');
        return res.status(401).json({ 
            status: 'error', 
            message: 'Refresh token missing', 
            data: null 
        });
    }

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
        console.log(`Refreshed access token for ${user.username}`);
        sendResponse(res, 'success', 'Access token refreshed', { username: user.username });
    } catch (err) {
        console.error('Refresh token invalid or expired:', err.message);
        res.status(403).json({ 
            status: 'error', 
            message: 'Invalid or expired refresh token', 
            data: null 
        });
    }
});

// ─── LOGOUT ─────────────────────────────────────────────────────────────────
app.post('/logout', (req, res) => {
    console.log('Logout attempt');
    const cookieOptions = { path: '/', sameSite: 'Strict' };
    res.clearCookie('accessToken', cookieOptions);
    res.clearCookie('refreshToken', cookieOptions);
    console.log('User logged out successfully');
    sendResponse(res, 'success', 'Logged out successfully');
});

// ─── START ───────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
    console.log(`🚀 Server running! Open http://localhost:${PORT} in your browser.`);
});