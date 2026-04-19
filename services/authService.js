import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { UserTypeModel } from "../models/userModel.js";
import { config } from "dotenv";
import { Error } from "mongoose";

config();

//register function
export const register=async(userObj)=>{
    //create document
    const userDocument=new UserTypeModel(userObj);
    //validate for empty passwords
    await userDocument.validate();
    //hash and replace the plain password
    userDocument.password=await bcrypt.hash(userDocument.password,12);
    //save userDocument in mongoDB database
    const created =await userDocument.save();
    //convert document to object to remove password
    const newUserobj=created.toObject();
    //remove the password
    delete newUserobj.password;
    //return userObj without password
    return newUserobj;
}

//authenticate function
export const authenticate = async (email, password) => {

  const user = await UserTypeModel.findOne({ email });

  if (!user) {
    const err = new Error("Invalid email");
    err.status = 401;
    throw err;
  }

  const isMatchedPassword = await bcrypt.compare(password, user.password);

  if (!isMatchedPassword) {
    const err = new Error("Invalid Password");
    err.status = 401;
    throw err;
  }

  if (!user.isActive) {
    const err = new Error("Your Account is blocked by the Admin");
    err.status = 403;
    throw err;
  }

  const token = jwt.sign(
    { userId: user._id, role: user.role },
    process.env.JWT_SECRET_KEY,
    { expiresIn: "1h" }
  );

  const userObj = user.toObject();
  delete userObj.password;

  return { token, user: userObj };
};
