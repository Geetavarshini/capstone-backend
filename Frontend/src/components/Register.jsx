import React from 'react';
import { useForm } from 'react-hook-form';
import { useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router';

function Register() {
  let { register, handleSubmit, formState: { errors } } = useForm();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [preview, setPreview] = useState(null);
  const [fileError, setFileError] = useState(null); // ✅ separate state for file errors

  let navigate = useNavigate();

  let onFormSubmit = async (newUser) => {
    setLoading(true); // ✅ add this
    const formData = new FormData();
    let { role, profileImageUrl, ...userObj } = newUser;
    Object.keys(userObj).forEach((key) => {
      formData.append(key, userObj[key]);
    });
    formData.append("profileImageUrl", profileImageUrl[0]);

    try {
      
      if (role === "USER") {
        let resObj = await axios.post('https://capstone-project-rbl1.onrender.com/user-api/users', formData);
        if (resObj.status === 201) {
          navigate("/login");
        }
      }
      if (role === "AUTHOR") {
        let resObj = await axios.post('https://capstone-project-rbl1.onrender.com/author-api/users', formData);
        if (resObj.status === 201) {
          navigate("/login");
        }
      }
    } catch (err) {
      const msg = err.response?.data?.message || err.message || "Something went wrong";
      setError(msg);
      console.error("Full Error Object:", err);
    } finally {
      setLoading(false);
    }
  };

  if (loading === true) {
    return <p className='text-black text-2xl'>Loading...</p>;
  }

  if (error != null) {
    return (
      <div className="text-center mt-10">
        <p className='text-red-700 text-3xl mb-4'>{error}</p>
        <button onClick={() => setError(null)} className="bg-blue-600 text-white p-2 rounded">
          Try Again
        </button>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 p-4">
      <div className="w-full max-w-md bg-gray-100 p-8 rounded-xl shadow-2xl">
        <form onSubmit={handleSubmit(onFormSubmit)}>
          <div className="mb-6 flex items-center justify-center bg-white p-3 rounded-lg border border-gray-200">
            <span className="me-4 font-semibold text-gray-700">Select Role:</span>
            <label className="flex items-center me-4 cursor-pointer">
              <input type="radio" value="USER" {...register("role", { required: "Please select a role" })} className="accent-blue-600 w-4 h-4" />
              <span className="ms-2">User</span>
            </label>
            <label className="flex items-center cursor-pointer">
              <input type="radio" value="AUTHOR" {...register("role", { required: "Please select a role" })} className="accent-blue-600 w-4 h-4" />
              <span className="ms-2">Author</span>
            </label>
          </div>
          {errors.role && <p className="text-red-500 block text-sm mt-1">{errors.role.message}</p>}

          <div className="grid grid-cols-2 gap-4 mb-4">
            <div>
              <input type="text" {...register("firstName", { required: "First name is required" })} placeholder="First Name" className="w-full border border-gray-300 p-2 rounded focus:outline-blue-400" />
              {errors.firstName && <p className="text-red-500 text-sm mt-1">{errors.firstName.message}</p>}
            </div>
            <div>
              <input type="text" {...register("lastName", { required: "Last name is required" })} placeholder="Last Name" className="w-full border border-gray-300 p-2 rounded focus:outline-blue-400" />
              {errors.lastName && <p className="text-red-500 text-sm mt-1">{errors.lastName.message}</p>}
            </div>
          </div>

          <div className="mb-4">
            <input type="email" {...register("email", { required: "Email is required" })} placeholder="Email Address" className="w-full border border-gray-300 p-2 rounded focus:outline-blue-400" />
            {errors.email && <p className="text-red-500 block text-sm mt-1">{errors.email.message}</p>}
          </div>

          <div className="mb-4">
            <input type="password" {...register("password", { required: "Password is required" })} placeholder="Password" className="w-full border border-gray-300 p-2 rounded focus:outline-blue-400" />
            {errors.password && <p className="text-red-500 block text-sm mt-1">{errors.password.message}</p>}
          </div>

          <div className="mb-6">
            <input
              type="file"
              accept="image/png, image/jpeg"
              {...register("profileImageUrl")}
              onChange={(e) => {
                const file = e.target.files[0];
                if (file) {
                  if (!["image/jpeg", "image/png"].includes(file.type)) {
                    setFileError("Only JPG or PNG allowed"); // ✅ use fileError
                    return;
                  }
                  if (file.size > 2 * 1024 * 1024) {
                    setFileError("File size must be less than 2MB"); // ✅ use fileError
                    return;
                  }
                  const previewUrl = URL.createObjectURL(file);
                  setPreview(previewUrl);
                  setFileError(null); // ✅ clear fileError
                }
              }}
            />
            {fileError && <p className="text-red-500 text-sm mt-1">{fileError}</p>} {/* ✅ inline error */}
            {preview && (
              <div className="mt-3 flex justify-center">
                <img src={preview} alt="Preview" className="w-24 h-24 object-cover rounded-full border" />
              </div>
            )}
          </div>

          <button type="submit" className="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded transition duration-300 shadow-md">
            Register
          </button>
        </form>
      </div>
    </div>
  );
}

export default Register;