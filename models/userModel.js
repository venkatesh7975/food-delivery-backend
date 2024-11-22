import mongoose from "mongoose";

const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    cartData: { type: Object, default: {} },
    resetToken: { type: String }, // Token for password reset
    resetExpires: { type: Date }, // Expiry time for reset token
    twoFactorCode: { type: String }, // Code for 2FA
    twoFactorExpires: { type: Date }, // Expiry time for 2FA code
  },
  { minimize: false }
);

const userModel = mongoose.models.user || mongoose.model("user", userSchema);
export default userModel;
