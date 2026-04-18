import { UserTypeModel } from "../models/userModel.js";

export const checkUser=async(req,res,next)=>{
    //get user id
    let userId= req.user.userId;
    //check user
    let userExists=await UserTypeModel.findById(userId);
    //if user not found
    if(!userExists){
        return res.status(401).json({message:"Invalid user"});
    }
    //if user found but role is differnet
    if(userExists.role !="USER"){
        return res.status(401).json({message:"trying to login with differnet role"});
    }
    //if user blocked
    if(!userExists.isActive){
        return res.status(401).json({message:" user account is not active"});
    }
    //forward req to next
    next();
}