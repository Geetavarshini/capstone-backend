import exp from 'express';
import { authenticate } from '../services/authService.js';
import { verifyToken } from '../middlewares/verifyToken.js';
import { compare,hash } from 'bcryptjs';
import { UserTypeModel } from '../models/userModel.js';

export const commonRoute=exp.Router();

//login
commonRoute.post("/authenticate",async(req,res)=>{
    //get user credential object
        let {email,password}=req.body;
        //call authenticate service
        let {token,user}= await authenticate(email,password);
        //save token as HTTPOnly cookie
        res.cookie("token",token,{
            httpOnly:true,
            sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
            secure:process.env.NODE_ENV === "production" ? true : false,
            maxAge: 3600000 // 1 hour
        });
        //send res
        res.status(201).json({message:"Login Success",payload:user});
})
//logout
commonRoute.get("/logout",async(req,res)=>{
    //clear the cookie named token
    //must match orginal set settings
    res.clearCookie('token',{
        httpOnly:true,
        sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
        secure:process.env.NODE_ENV === "production" ? true : false,
        maxAge: 3600000 // 1 hour
    })
    res.status(200).json({message:"Logged Out Successfully"});
})

//change password
commonRoute.put("/change-password/:userId",verifyToken,async(req,res)=>{
    //get user id from req
    let userId=req.params.userId;
    let userDoc=await UserTypeModel.findById(userId);
    if(!userDoc){
        return res.status(401).json({message:"Invalid User"});
    }
    //get the current pass and new pass from req
    let {currentPassword,newPassword}=req.body;
    //check the current password is correct or not
    let checkPassword=await compare(currentPassword,userDoc.password);
    if(!checkPassword){
        return res.status(400).json({message:"Password not matched "});
    }
    //replace current password with new password
    //hash new password
    let hashedPassword=await hash(newPassword,12)
    let updated=await UserTypeModel.findByIdAndUpdate(userId,{$set:{password:hashedPassword}})
    return res.status(200).json({message:"Password changed successfully"});
})



//page refresh
commonRoute.get("/check-auth",verifyToken("USER","AUTHOR","ADMIN"),async(req,res)=>{
 res.status(200).json({message:"User is authenticated",payload:req.user});   
})