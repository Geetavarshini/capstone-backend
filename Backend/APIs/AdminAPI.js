import exp from 'express';
export const adminRoute=exp.Router();

import { verifyToken } from '../middlewares/verifyToken.js';
import { checkAuthor } from '../middlewares/checkAuthor.js';
import { UserTypeModel } from '../models/userModel.js';



//block users
//route handler to block users 
adminRoute.put("/block/:userId",verifyToken,async(req,res)=>{
    //get userid from req
    let userId=req.params.userId;
    //check user exists in database
    let userExists =await UserTypeModel.findById(userId);
    //if user not found send res as user not found
    if(!userExists){
        return res.status(401).json({message:"Invalid User"});
    }
    //if user exists but already blocked by admin(isActive=false)
    if(!userExists.isActive){
        return res.status(401).json({message:"User is Already Blocked by Admin"})
    }
    //find the user by id and update 
    let blockUser=await UserTypeModel.findByIdAndUpdate(userId,{$set:{isActive:false}})
    //send response 
    return res.status(200).json({message:"User Blocked",payload:blockUser});

})
//unblock users
adminRoute.put("/unblock/:userId",verifyToken,async(req,res)=>{
    //get userid from req
    let userId=req.params.userId;
    //check user exists in database
    let userExists=await UserTypeModel.findById(userId);
    //if user not found send res as user not found
     if(!userExists){
        return res.status(401).json({message:"Invalid User"});
    }
    if(userExists.isActive){
        return res.status(401).json({message:"User is  not blocked by Admin"})
    }
    //find the user by id and update 
    let unBlockUser=await UserTypeModel.findByIdAndUpdate(userId,{$set:{isActive:true}});
    //send response
    return res.status(200).json({message:"User Unblocked",payload:unBlockUser});
})