const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { getUserModel, getUsernameField, getPasswordField, getEmailField } = require('./db');
const { OAuth2Client } = require('google-auth-library');
const { getConfig } = require('./config');


const generateTokens = (user, type) => {
    let payload;
    const { JWT_SECRET_KEY } = getConfig()

    if (type === 0) {
        payload = { [getEmailField()]: user[getEmailField()] }
    } else if (type === 1){
        payload = { [getUsernameField()]: user[getUsernameField()] }
    }
    console.log(payload);
    
    const accessToken = jwt.sign(payload, JWT_SECRET_KEY, { expiresIn: '15m' });
    const refreshToken = jwt.sign(payload, JWT_SECRET_KEY, { expiresIn: '7d' });
    return { accessToken, refreshToken };
}

const signup = async (req, res) => {
    try {
        console.log('came here');
        
        const User = getUserModel();
        const username = req.body[getUsernameField()];
        const password = req.body[getPasswordField()];

        const existingUser = await User.findOne({ [getUsernameField()]: username });
        if (existingUser) {
            return res.status(400).json({ message: 'User already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ [getUsernameField()]: username, [getPasswordField()]: hashedPassword });
        await newUser.save();

        res.status(201).json({ message: 'User created successfully' });
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ message: error.message });
    }
};

const login = async (req, res) => {
    try {
        const User = getUserModel();
        const username = req.body[getUsernameField()];
        const password = req.body[getPasswordField()];

        const user = await User.findOne({ [getUsernameField()]: username });
        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        const isPasswordValid = await bcrypt.compare(password, user[getPasswordField()]);
        if (!isPasswordValid) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        const { accessToken, refreshToken } = generateTokens(user, 1);
        res.cookie('accessToken', accessToken, {
            httpOnly: true,
            maxAge: 3600000,
            secure: true,
            sameSite: 'None'
        });
        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            maxAge: 259200000,
            secure: true,
            sameSite: 'None'
        });

        res.status(200).json({ message: 'Login successful' });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: error.message });
    }
};

const loginRequired = async (req, res, next) => {
    console.log('checkingn\n\n\n\n\n');
    
    const { accessToken, refreshToken } = req.cookies;
    const { JWT_SECRET_KEY } = getConfig()

    try {
        jwt.verify(accessToken, JWT_SECRET_KEY, async (err, decoded) => {
            if (err && (err.name === 'TokenExpiredError' || err.name === 'JsonWebTokenError') && refreshToken) {
                jwt.verify(refreshToken, JWT_SECRET_KEY, async (refreshErr, refreshDecoded) => {
                    if (refreshErr) {
                        return res.status(401).json({ message: 'Refresh token invalid or expired' });
                    }

                    const User = getUserModel();
                    let user;
                    if (decoded[getUsernameField()]) {
                        user = await User.findOne({[getUsernameField()]: decoded[getUsernameField()]});
                    } else if (decoded[getEmailField()]) {
                        user = await User.findOne({[getEmailField()]: decoded[getEmailField()]});
                    }
                    console.log(user);
                    
                    if (!user) {
                        return res.status(401).json({ message: 'User not found' });
                    }
                    let newAccessToken;
                    if (refreshDecoded[getEmailField()]) {
                        newAccessToken = generateTokens(refreshDecoded,0).accessToken;
                    } else {
                        newAccessToken = generateTokens(refreshDecoded,1).accessToken;
                    }
                    res.cookie('accessToken', newAccessToken, {
                        httpOnly: true,
                        maxAge: 3600000,
                        secure: true,
                        sameSite: 'None'
                    });
                    req.user = user;
                    next();
                });
            } else if (err) {
                return res.status(401).json({ message: 'Invalid access token' });
            } else {
                console.log(decoded);
                
                const User = getUserModel();
                const user = await User.findOne({
                    $or: [
                        { [getUsernameField()]: decoded[getUsernameField()] },
                        { [getEmailField()]: decoded[getEmailField()] }
                    ]
                });
                
                if (!user) {
                    return res.status(401).json({ message: 'User not found' });
                }
                req.user = decoded;
                next();
            }
        });
    } catch (error) {
        console.error('Authentication middleware error:', error);
        res.status(500).json({ message: error.message });
    }
};

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: 'Too many login attempts from this IP, please try again later.',
    handler: (req, res) => {
        res.status(429).json({
            error: 'Too many login attempts from this IP, please try again later.'
        });
    }
});

const verifyGoogleToken = async (tokenId, GOOGLE_CLIENT_ID)=> {
    const client = new OAuth2Client(GOOGLE_CLIENT_ID); // Replace with your Google Client ID
    const ticket = await client.verifyIdToken({
        idToken: tokenId,
        audience: GOOGLE_CLIENT_ID, // Replace with your Google Client ID
    });
    const payload = ticket.getPayload();
    console.log(payload);
    

    return payload;
}

const googleLogin = async (req, res)=> {
    const { tokenId } = req.body;
    const { GOOGLE_CLIENT_ID } = getConfig()


    try {
        const payload = await verifyGoogleToken(tokenId, GOOGLE_CLIENT_ID);
        const User = getUserModel();
        const emailField = getEmailField();
        let user = await User.findOne({ [emailField]: payload.email });

        if (!user) {
            user = new User({
                [emailField]: payload.email,
            });
            await user.save();
        }

        // Generate tokens
        const { accessToken, refreshToken } = generateTokens(user, 0);
        res.cookie('accessToken', accessToken, {
            httpOnly: true,
            maxAge: 3600000,
            secure: true,
            sameSite: 'None'
        });
        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            maxAge: 259200000,
            secure: true,
            sameSite: 'None'
        });

        res.status(200).json({ message: 'Login successful', user });
    } catch (error) {
        console.error('Google login error:', error);
        res.status(401).json({ message: 'Invalid Google token' });
    }
}

const logout = async (req, res)=> {
    res.cookie('accessToken', null, {
      httpOnly: true,
      maxAge: -1, // Immediate expiration
      secure: true,   // Set to true in production with HTTPS
      sameSite: 'None' // Set 'SameSite' to 'None' for cross-site cookies
    });
    res.cookie('refreshToken', null, {
      httpOnly: true,
      maxAge: -1,
      secure: true,   // Set to true in production with HTTPS
      sameSite: 'None' // Set 'SameSite' to 'None' for cross-site cookies
    });
    res.json({ message: 'Logout successful' });
};

module.exports = { signup, login, loginRequired, googleLogin, loginLimiter, logout };
