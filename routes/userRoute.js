import express from "express";
import {
  loginUser,
  registerUser,
  forgotPassword,
  resetPassword,
  verifyTwoFactor,
} from "../controllers/userController.js";

const userRouter = express.Router();

// Register a new user
userRouter.post("/register", registerUser);

// Login user
userRouter.post("/login", loginUser);

// Forgot password
userRouter.post("/forgot-password", forgotPassword);

// Reset password
userRouter.post("/reset-password/:token", resetPassword);

// Verify 2FA code
userRouter.post("/verify-2fa", verifyTwoFactor);

export default userRouter;
