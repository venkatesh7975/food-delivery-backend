import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import validator from "validator";
import crypto from "crypto";
import nodemailer from "nodemailer";
import userModel from "../models/userModel.js";
import dotenv from "dotenv";

dotenv.config();

// Create token
const createToken = (id) => {
    return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: "7d" });
};

// Email transporter for sending reset and 2FA codes
const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.EMAIL,
        pass: process.env.EMAIL_PASSWORD,
    },
});

// Login user
const loginUser = async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await userModel.findOne({ email });

        if (!user) {
            return res.json({ success: false, message: "User does not exist" });
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.json({ success: false, message: "Invalid credentials" });
        }

        // Generate a 2FA code
        const twoFactorCode = crypto.randomInt(100000, 999999).toString();
        user.twoFactorCode = twoFactorCode;
        user.twoFactorExpires = Date.now() + 10 * 60 * 1000; // Expires in 10 minutes
        await user.save();

        // Send 2FA code via email
        await transporter.sendMail({
            from: process.env.EMAIL,
            to: user.email,
            subject: "Your Two-Factor Authentication Code",
            text: `Your authentication code is: ${twoFactorCode}`,
        });

        res.json({ success: true, message: "2FA code sent to email" });
    } catch (error) {
        console.log(error);
        res.json({ success: false, message: "Error" });
    }
};

// Verify 2FA and return token
const verifyTwoFactor = async (req, res) => {
    const { email, code } = req.body;
    try {
        const user = await userModel.findOne({ email });

        if (!user || user.twoFactorCode !== code || user.twoFactorExpires < Date.now()) {
            return res.json({ success: false, message: "Invalid or expired 2FA code" });
        }

        user.twoFactorCode = null; // Clear the code after verification
        user.twoFactorExpires = null;
        await user.save();

        const token = createToken(user._id);
        res.json({ success: true, token });
    } catch (error) {
        console.log(error);
        res.json({ success: false, message: "Error" });
    }
};

// Register user
const registerUser = async (req, res) => {
    const { name, email, password } = req.body;
    try {
        // Check if user already exists
        const exists = await userModel.findOne({ email });
        if (exists) {
            return res.json({ success: false, message: "User already exists" });
        }

        // Validate email format & strong password
        if (!validator.isEmail(email)) {
            return res.json({ success: false, message: "Please enter a valid email" });
        }
        if (password.length < 8) {
            return res.json({ success: false, message: "Please enter a strong password" });
        }

        // Hash user password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = new userModel({ name, email, password: hashedPassword });
        const user = await newUser.save();
        const token = createToken(user._id);
        res.json({ success: true, token });
    } catch (error) {
        console.log(error);
        res.json({ success: false, message: "Error" });
    }
};

// Forgot password
const forgotPassword = async (req, res) => {
    const { email } = req.body;
    try {
        const user = await userModel.findOne({ email });
        if (!user) {
            return res.json({ success: false, message: "User not found" });
        }

        // Generate reset token and expiration
        const resetToken = crypto.randomBytes(32).toString("hex");

        user.resetToken = resetToken;
        user.resetExpires = Date.now() + 10 * 60 * 1000; // Token valid for 10 minutes
        await user.save();

        // Send reset link via email
        const resetUrl = `https://food-delivery-frontend-red.vercel.app/reset-password/${resetToken}`;
        await transporter.sendMail({
            from: process.env.EMAIL,
            to: user.email,
            subject: "Password Reset Request",
            text: `Click the link to reset your password: ${resetUrl}. This link is valid for 10 minutes.`,
        });

        res.json({ success: true, message: "Password reset link sent to email" });
    } catch (error) {
        console.log(error);
        res.json({ success: false, message: "Error" });
    }
};

// Reset password
const resetPassword = async (req, res) => {
    const { token } = req.params;
    const { password } = req.body;
    try {
        const user = await userModel.findOne({
            resetToken: token, // Compare the plain token
            resetExpires: { $gt: Date.now() }, // Ensure token is not expired
        });

        if (!user) {
            return res.json({ success: false, message: "Token is invalid or expired" });
        }

        // Hash new password and update
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        user.password = hashedPassword;
        user.resetToken = null; // Clear reset token
        user.resetExpires = null;
        await user.save();

        res.json({ success: true, message: "Password reset successful" });
    } catch (error) {
        console.log(error);
        res.json({ success: false, message: "Error" });
    }
};

export { loginUser, registerUser, forgotPassword, resetPassword, verifyTwoFactor };
