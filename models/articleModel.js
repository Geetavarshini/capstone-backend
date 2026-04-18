import { Schema,model } from "mongoose";

//create user comment Schema
const userCommentSchema =new Schema({
    user:{
        type:Schema.Types.ObjectId,
        ref:'User'
    },
    comment:{
        type:String
    }
})

//create article schema
const articleSchema=new Schema({
    author:{
        type:Schema.Types.ObjectId,
        ref:'User',
        required:[true,"Author ID required"]
    },
    title:{
        type:String,
        required:[true,"Title name is required"]
    },
    category:{
        type:String,
        required:[true,"Category is required"]
    },
    content:{
        type:String,
        required:[true,"Content is required"]
    },
    comments:[userCommentSchema],
    isArticleActive:{
        type:Boolean,
        default:true
    }
},{
    strict:"throw",
    timestamps:true,
    versionKey:false
}
)
export const ArticleModel=model('Article',articleSchema);