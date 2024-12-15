import { rateLimit } from 'express-rate-limit'

export const resetOtpLimiter = rateLimit({
	windowMs: 5 * 60 * 1000,
	max: 5,
    message: 'Too many otp requests, please try again after 5 minutes!',
	standardHeaders: true, 
	legacyHeaders: false, 
});

export const resetPasswordLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: 'Too many reset password requests, try again after 15 minutes',
    standardHeaders: true,
    legacyHeaders: false
});