import React from 'react';
import { useForm } from 'react-hook-form';
import axios from 'axios';
import { toast } from 'react-hot-toast';

function EditArticle({ article, setArticle, setIsEditing }) {
  // 1. Initialize form with existing article data
  const { register, handleSubmit, watch, formState: { isSubmitting } } = useForm({
    defaultValues: {
      title: article?.title,
      category: article?.category,
      content: article?.content
    }
  });

  const selectedCategory = watch("category");

  // 2. Submit handler matched to your BACKEND logic
  const onSubmit = async (data) => {
    // Construct the payload exactly as your backend expects:
    // { articleId, title, category, content }
    const finalData = {
      articleId: article._id, 
      title: data.title,
      category: data.category === "Other" ? data.customCategory : data.category,
      content: data.content
    };

    try {
      // URL is just '/articles' because your backend doesn't use /:id params
      const BASE_URL = import.meta.env.VITE_API_URL;
      const res = await axios.put(
        'https://capstone-project-rbl1.onrender.com/author-api/articles', 
        finalData, 
        { withCredentials: true }
      );
      
      if (res.data.payload) {
        // Update the view state in ArticleDetail
        setArticle(res.data.payload);
        // Switch back to Article Detail view
        setIsEditing(false);
        toast.success("Article Updated Successfully");
      }
    } catch (err) {
      console.error("Update Error:", err);
      toast.error(err.response?.data?.message || "Update failed");
    }
  };

  return (
    <div className="animate-in fade-in duration-500">
      <header className="mb-10">
        <h2 className="text-3xl font-black text-gray-900">Edit <span className="text-blue-600">Story</span></h2>
        <p className="text-gray-400 text-sm mt-1">Update your content and save changes below.</p>
      </header>

      <form onSubmit={handleSubmit(onSubmit)} className="space-y-8">
        
         {/* HEADLINE */}
        <div>
          <label className="text-[10px] font-bold text-gray-400 uppercase tracking-widest mb-3 block">Title</label>
          <input 
            {...register("title", { required: true })} 
            className="text-4xl font-black w-full border-none outline-none focus:ring-0 placeholder:text-gray-200"
            placeholder="Article Title"
          />
        </div>

        {/* STORY CONTENT */}
        <div>
        {/* TOPIC / CATEGORY */}
        <div>
          <label className="text-[10px] font-bold text-gray-400 uppercase tracking-widest mb-3 block">Category</label>
          <select 
            {...register("category", { required: true })}
            className="w-full p-3 bg-gray-50 border-none rounded-xl text-sm font-semibold outline-blue-600 cursor-pointer"
          >
            <option value="Programming">Programming</option>
            <option value="AI">AI</option>
            <option value="Lifestyle">Lifestyle</option>
            <option value="Other">Other</option>
          </select>

          {/* Show custom input if "Other" is selected */}
          {selectedCategory === "Other" && (
            <input 
              {...register("customCategory", { required: true })} 
              placeholder="Enter your custom topic..."
              className="mt-3 w-full p-3 bg-gray-50 border-b-2 border-blue-100 outline-none text-sm font-semibold"
            />
          )}
        </div>

       
          <label className="text-[10px] font-bold text-gray-400 uppercase tracking-widest mb-3 block">Content</label>
          <textarea 
            {...register("content", { required: true })} 
            rows="12"
            className="w-full border-none outline-none text-lg leading-relaxed text-gray-800 placeholder:text-gray-200 resize-none"
            placeholder="Write your content here..."
          />
        </div>

        {/* FORM ACTIONS */}
        <div className="flex gap-4 pt-6">
          <button 
            type="submit" 
            disabled={isSubmitting}
            className="flex-grow bg-blue-600 text-white font-bold py-4 rounded-2xl hover:bg-blue-700 transition-all shadow-lg shadow-blue-100 disabled:bg-gray-300"
          >
            {isSubmitting ? "Processing..." : "Update Story"}
          </button>
          
          <button 
            type="button" 
            onClick={() => setIsEditing(false)} 
            className="px-8 py-4 text-gray-400 font-bold hover:bg-gray-100 rounded-2xl transition-all"
          >
            Cancel
          </button>
        </div>
      </form>
    </div>
  );
}

export default EditArticle;