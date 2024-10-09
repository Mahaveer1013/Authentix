const bcrypt = require('bcrypt');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { getEmailField } = require('./db');

const saltRounds = 10;
const otpExpiryTime = 300000; // 5 minutes

const otpStore = {}; // In-memory storage for OTPs

const transporter = nodemailer.createTransport({
    service: 'Gmail',
    auth: {
        user: 'panimalar1013@gmail.com',
        pass: 'xlfljsucefujwwkc',
    },
});

const sendOtpEmail = (email, otp) => {
    const mailOptions = {
        from: 'mahaveer',
        to: email,
        subject: 'Your OTP Code',
        text: `Your OTP code is ${otp}`,
    };

    return transporter.sendMail(mailOptions);
};

const emailSignup = async (email, password) => {
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const otp = crypto.randomBytes(3).toString('hex');
    const otpExpires = Date.now() + otpExpiryTime;

    otpStore[email] = { otp, otpExpires, hashedPassword };

    await sendOtpEmail(email, otp);

    return { success: true, message: 'Signup successful, OTP sent to email' };
};

const verifyOtp = async (email, otp) => {
    const storedOtpData = otpStore[email];

    if (!storedOtpData || storedOtpData.otp !== otp || storedOtpData.otpExpires < Date.now()) {
        return { success: false, message: 'Invalid or expired OTP' };
    }

    const { hashedPassword } = storedOtpData;
    delete otpStore[email]; // Remove OTP from store after verification

    const User = getUserModel();
    const existingEmail = req.body[getEmailField()];

    const existingUser = await User.findOne({ [getEmailField()]: existingEmail });
    if (existingUser) {
        return res.status(400).json({ message: 'Email already exists' });
    }

    const newUser = new User({ [getEmailField()]: email, [getPasswordField()]: hashedPassword });
    await newUser.save();

    return { success: true, message: 'OTP verified, user registered', hashedPassword };
};

module.exports = {
    emailSignup,
    verifyOtp,
};
