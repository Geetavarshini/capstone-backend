import { UserTypeModel } from "../models/userModel.js";

export const checkAuthor=async (req,res,next)=>{
    //get author id
    let authorId=req.user.userId;
    //verify author
    //check the author
        let authorExists=await UserTypeModel.findById(authorId);
    //if author not found
    if(!authorExists){
        return res.status(401).json({message:"Invalid Author"});
    }
    //if author found but role is differnet
    if(authorExists.role !="AUTHOR"){
        return res.status(401).json({message:"User is not an Author"});
    }
    //if author blocked
    if(!authorExists.isActive){
        return res.status(401).json({message:" Author account is not active"});
    }
    //forward req to next
    next();
}