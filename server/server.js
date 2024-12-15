import express from 'express'
import 'dotenv/config'
import cors from 'cors'
import cookieParser from 'cookie-parser'
import connectDB from './config/mongodb.js';
import authRouter from './routes/authRoutes.js';
import userRouter from './routes/userRoutes.js';

const app = express();
const port = process.env.PORT || 3000;
connectDB();

const allowedOrigins = ['https://auth-project-jnrtikx96-deepaksingh128367-gmailcoms-projects.vercel.app/']

app.use(express.json());
app.use(cors({origin: allowedOrigins, credentials: true }));
app.use(cookieParser());

app.get('/', (req, res) => res.send("API is working"));
app.use('/api/auth', authRouter);
app.use('/api/user', userRouter);

app.listen(port, () => {
    console.log(`Server is successfully started at port: ${port}`);
});