import userModel from "../models/userModel.js";

export const createUser = async ({ name, email, password }) => {
    try {
        const newUser = await userModel.create({
            name, 
            email,
            password
        });

        return newUser;
    } catch (error) {
        res.status(400).json({ message: "Error in creating user"})
    }
}