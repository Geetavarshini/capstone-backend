
import exp from 'express';
import { authenticate } from '../services/authService.js';
import { verifyToken } from '../middlewares/verifyToken.js';
import { compare, hash } from 'bcryptjs';
import { UserTypeModel } from '../models/userModel.js';

export const commonRoute = exp.Router();

// ===================== LOGIN =====================
commonRoute.post("/authenticate", async (req, res) => {
  try {
    const { email, password } = req.body;

    const { token, user } = await authenticate(email, password);

   
    res.cookie("token", token, {
      httpOnly: true,
      sameSite: "none",   // REQUIRED for cross-origin (Vercel → Render)
      secure: true,       // REQUIRED for HTTPS
      maxAge: 3600000     // 1 hour
    });

    res.status(200).json({
      message: "Login Success",
      payload: user
    });

  } catch (err) {
    console.log("🔥 LOGIN ERROR:", err);

    res.status(err.status || 500).json({
      message: err.message,
      fullError: err
    });
  }
});


// ===================== LOGOUT =====================
commonRoute.get("/logout", async (req, res) => {
  res.clearCookie("token", {
    httpOnly: true,
    sameSite: "none",
    secure: true
  });

  res.status(200).json({ message: "Logged Out Successfully" });
});


// ===================== CHANGE PASSWORD =====================
commonRoute.put("/change-password/:userId", verifyToken, async (req, res) => {
  const userId = req.params.userId;

  const userDoc = await UserTypeModel.findById(userId);
  if (!userDoc) {
    return res.status(401).json({ message: "Invalid User" });
  }

  const { currentPassword, newPassword } = req.body;

  const checkPassword = await compare(currentPassword, userDoc.password);
  if (!checkPassword) {
    return res.status(400).json({ message: "Password not matched" });
  }

  const hashedPassword = await hash(newPassword, 12);

  await UserTypeModel.findByIdAndUpdate(userId, {
    $set: { password: hashedPassword }
  });

  return res.status(200).json({ message: "Password changed successfully" });
});


// ===================== CHECK AUTH =====================
commonRoute.get(
  "/check-auth",
  verifyToken("USER", "AUTHOR", "ADMIN"),
  async (req, res) => {
    try {
      const user = await UserTypeModel
        .findById(req.user.userId)
        .select("-password");

      res.status(200).json({
        message: "User is authenticated",
        payload: user
      });
    } catch (err) {
      res.status(500).json({
        message: "Error fetching user",
        error: err.message
      });
    }
  }
);

