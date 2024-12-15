import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'

import { signupSchema, signinSchema, verifyOtpSchema, resetOtpSchema, resetPasswordSchema } from "../config/authSchema.js"
import userModel from "../models/userModel.js";
import { createUser } from '../services/userService.js';
import { transporter } from '../config/nodemailer.js';
import { EMAIL_VERIFY_TEMPLATE, PASSWORD_RESET_TEMPLATE } from '../config/emailTemplates.js';

export const register = async (req, res) => {
    const validatedData = signupSchema.safeParse(req.body);

    if(!validatedData.success) {
        const validationErrors = validatedData.error.errors;

        return res.json({success: false, message: validationErrors.message });
    }

    try {
        const userData = validatedData.data;

        const isUserAlreadyExist = await userModel.findOne({ email: userData.email });
        if(isUserAlreadyExist) {
            return res.json({success: false, message: "User already exists"});
        }

        const hashedPassword = await bcrypt.hash(userData.password, 10);
        
        const user = await createUser({
            name: userData.name,
            email: userData.email,
            password: hashedPassword
        });

        const token  = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d'});
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000 
        });

        // Sending welcome email
        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: "Welcome to Authentication Website",
            text: `Welcome to authentication website. Your account has been
            created successfully with email: ${user.email}`
        }

        await transporter.sendMail(mailOptions);

        res.json({ success: true, message: "User created"});
    } catch (error) {
        res.json({ success: false, message: error.message });
    }
}


export const login = async (req, res) => {
    const validatedData = signinSchema.safeParse(req.body);

    if(!validatedData.success) {
        const validationErrors = validatedData.error.errors;

        return res.json({success: false, message: validationErrors.message});
    }

    try {
        const userData = validatedData.data;
        const user = await userModel.findOne({ email: userData.email });
        if(!user) {
            return res.json({success:false, message: "User or Email is incorrect" });
        }

        const isMatch = await bcrypt.compare(userData.password, user.password);
        if(!isMatch){
            return res.json({success:false, message: "Email or password is incorrect"});
        }

        const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        res.json({ success: true, message: "Logged In"});

    } catch (error) {
        res.json({ success: false, message: error.message} );
    }
}


export const logout = async (req, res) => {
    try {
        res.clearCookie('token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict'
        });

        res.json({ success: true, message: "Logged out" });
    } catch (error) {
        res.json({ success: false, message: error.message });
    }
}

// send otp for email verification
export const sendVerifyOtp = async (req, res) => {
    try {
        const { userId } = req.body;

        const user = await userModel.findById(userId);

        if(user.isAccountVerified){
            return res.json({ success: false, message: "Account already verified!"})
        }

        const otp = String(Math.floor(100000 + Math.random() * 900000));
        
        user.verifyOtp = otp;
        user.verifyOtpExpireAt = Date.now() + 24 * 60 * 60 * 1000;

        await user.save();

        const mailOption = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: "Account Verification OTP",
            html: EMAIL_VERIFY_TEMPLATE.replace("{{otp}}", otp).replace("{{email}}", user.email),
        }

        await transporter.sendMail(mailOption);

        res.json({ success: true, message: "Verification otp sent on Email"} );
    } catch (error) {
        res.json({ success: false, message: error.message });
    }
}

// Verify the email
export const verifyEmail = async (req, res) => {
    const verifyData = verifyOtpSchema.safeParse(req.body);

    if (!verifyData.success) {
        return res.json({ success: false, message: "Missing details" });
    }
    const userId = verifyData.data.userId;
    const otp = verifyData.data.otp;

    try {
        const user = await userModel.findById(userId);
        if (!user) {
            return res.json({ success: false, message: "User not found" });
        }

        if (user.isAccountVerified) {
            return res.json({ success: false, message: "Already verified" });
        }
        
        if (user.verifyOtp === '' || user.verifyOtp !== otp) {
            return res.json({ success: false, message: "Invalid OTP" });
        }

        if (user.verifyOtpExpireAt < Date.now()) {
            return res.json({ success: false, message: "OTP expired" });
        }

        user.isAccountVerified = true;
        user.verifyOtp = '';
        user.verifyOtpExpireAt = 0;

        await user.save();

        res.json({ success: true, message: "Email verified successfully" });
    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
}

// Check if user is Authenticated
export const isAuthenticated = async (req, res) => {
    try {
        res.json({ success: true });
    } catch (error) {
        res.json({ success: false, message: error.message });
    }
}

// send password reset otp
export const sendResetOtp = async (req, res) => {
    const resetData = resetOtpSchema.safeParse(req.body);
    if (!resetData.success) {
        return res.json({ success: false, message: "Email is required" });
    }
    const email = resetData.data.email;

    try {
        const user = await userModel.findOne({ email });
        if (!user) {
            return res.json({ success: false, message: "User not found" });
        }    

        const otp = String(Math.floor(100000 + Math.random() * 900000));
        user.resetOtp = otp;
        user.resetOtpExpireAt = Date.now() + 15 * 60 * 1000;

        await user.save();

        const mailOption = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: "Password reset OTP",
            html: PASSWORD_RESET_TEMPLATE.replace("{{otp}}", otp).replace("{{email}}", user.email)
        }

        await transporter.sendMail(mailOption);

        res.json({ success: true, message: "OTP sent to your Email" });
    } catch (error) {
        return res.json({ success: false, message: error.message });    
    }
}

// Reset user Password
export const resetPassword = async (req, res) => {
    const resetPassData = resetPasswordSchema.safeParse(req.body);
    if (!resetPassData.success) {
        return res.json({ success: false, message: "Email, OTP and  new password are required." });
    }

    const email = resetPassData.data.email;
    const otp = resetPassData.data.otp;
    const newPassword = resetPassData.data.newPassword;

    try {
        const user = await userModel.findOne({ email });
        if (!user) {
            return res.json({ success: false, message: "User not found "});
        }

        if (user.resetOtp === "" || user.resetOtp !== otp) {
            return res.json({ success: false, message: "Invalid OTP" });
        }

        if (user.resetOtpExpireAt < Date.now()) {
            return res.json({ success: false, message: "OTP expired" });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        user.password = hashedPassword;
        user.resetOtp = '';
        user.resetOtpExpireAt = 0;

        await user.save();

        res.json({ success: true, message: "Password has been reset successfully" });
    } catch (error) {
        res.json({ success: false, message: error.message });
    }
}