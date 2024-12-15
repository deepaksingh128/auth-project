import z, { literal } from 'zod';

export const signupSchema = z.object({
    name: z.string({
        required_error: "Name is required"
    }).min(1, "Name cannot be empty"),

    email: z.string({
        required_error: "Email is required"
    }).email("Invalid email format"),

    password: z.string({
        required_error: "Password is required"
    }).min(6, "Password must be 6 characters long"),

    verifyOtp: z.string().optional().or(z.literal("")),

    verifyOtpExpireAt: z.number().optional(),

    isAccountVerified: z.boolean().default(false),

    resetOtp: z.string().optional().or(z.literal("")),

    resetOtpExpireAt: z.number().optional(),
});

export const signinSchema = z.object({
    email: z.string({
        required_error: "Email is required"
    }).email("Invalid email format"),

    password: z.string({
        required_error: "Password is required"
    })
}); 

export const verifyOtpSchema = z.object({
    userId: z.string(),
    otp: z.string()
});

export const resetOtpSchema = z.object({
    email: z.string()
});

export const resetPasswordSchema = z.object({
    email: z.string(),
    otp: z.string(),
    newPassword: z.string()
});