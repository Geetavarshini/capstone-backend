import jwt from "jsonwebtoken";
import { config } from "dotenv";
config();

export const verifyToken=(... allowedRoles)=>{
    return async(req,res,next)=>{
    try{
        //read token from req
        let token=req.cookies?.token;//{token:" "}
        if(token === undefined){
            return res.status(400).json({message:"Unauthorized .Please Login"})
        }
        //verify the validility of the token(decoding token)
        let decodedToken=jwt.verify(token,process.env.JWT_SECRET_KEY);
        //check if role is allowed
        if(!allowedRoles.includes(decodedToken.role)){
            return res.status(403).json({message:"Forbidden.You dont have permission"})
        }
        //store decoded token in req.user so that we can have userid and role
        req.user=decodedToken;
        //forward req to next middleware or routr
        next();
    }catch(err){
        //jwt.verify throws if token is invalid or expired\
        if(err.name==="TokenExpiredError"){
            return res.status(401).json({message:"Session Expired.Please Login"});
        }
        if(err.name === "JsonWebTokenError"){
            return res.status(401).json({message:"Invalid Token. Please Login"});
        }
        // next(err); used to parse req to other error handling middleware
    }
}
}