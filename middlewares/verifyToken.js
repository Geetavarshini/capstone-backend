import jwt from "jsonwebtoken";
import { config } from "dotenv";

config();

export const verifyToken = (...allowedRoles) => {
  return async (req, res, next) => {
    try {
      //  Read token from cookies
      const token = req.cookies?.token;

      if (!token) {
        return res.status(401).json({
          message: "Unauthorized. Please login"
        });
      }

      // Verify token
      const decodedToken = jwt.verify(
        token,
        process.env.JWT_SECRET_KEY
      );

      // Role check
      if (!allowedRoles.includes(decodedToken.role)) {
        return res.status(403).json({
          message: "Forbidden. You don't have permission"
        });
      }

      //Attach user to request
      req.user = decodedToken;

      next();
    } catch (err) {
      console.log("VERIFY TOKEN ERROR:", err);

      if (err.name === "TokenExpiredError") {
        return res.status(401).json({
          message: "Session expired. Please login again"
        });
      }

      if (err.name === "JsonWebTokenError") {
        return res.status(401).json({
          message: "Invalid token. Please login"
        });
      }

      //fallback error
      return res.status(500).json({
        message: "Server error in token verification"
      });
    }
  };
};

