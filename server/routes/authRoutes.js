import express from 'express'
import { isAuthenticated, login, logout, register, resetPassword, sendResetOtp, sendVerifyOtp, verifyEmail } from '../controllers/authController.js';
import userAuth from '../middlewares/userAuth.js';
import { resetOtpLimiter, resetPasswordLimiter} from '../middlewares/rateLimiters.js'

const authRouter = express.Router();

authRouter.post('/register', register);
authRouter.post('/login', login);
authRouter.post('/logout', logout);
authRouter.post('/send-verify-otp', userAuth, sendVerifyOtp);
authRouter.post('/verify-account', userAuth, verifyEmail);
authRouter.get('/is-auth',userAuth, isAuthenticated); 
authRouter.post('/send-reset-otp',resetOtpLimiter, sendResetOtp);
authRouter.post('/reset-password',resetPasswordLimiter, resetPassword);

export default authRouter;