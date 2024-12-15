import jwt from 'jsonwebtoken'

const userAuth = async (req, res, next) => {
    const { token } = req.cookies;

    if (!token) {
        return res.json({ success: false, message: "Not Authorized, login again!" });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        if(decoded._id) {
            req.body.userId = decoded._id;
            return next();
        }else{
            res.json({ success: false, message: "Not Authorized, login again" });
        }

    } catch (error) {
        res.json({ success: false, message: error.message });
    }
}

export default userAuth;