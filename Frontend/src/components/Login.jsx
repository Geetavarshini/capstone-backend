import React, { useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { useAuth } from '../AuthStore/useAuth';
import { useNavigate } from 'react-router';
import { toast } from 'react-hot-toast';

function Login() {
  // 1. Initialize form with validation mode
  const { register, handleSubmit, formState: { errors } } = useForm({
    mode: 'onTouched'
  });

  const login = useAuth((state) => state.login);
  const isAuthenticated = useAuth((state) => state.isAuthenticated);
  const currentUser = useAuth((state) => state.currentUser);
  const error = useAuth((state) => state.error); // Get server-side error from Zustand
  const loading = useAuth((state) => state.loading); // Get loading state
  const navigate = useNavigate();

  const onLoginSubmit = async (userCredObj) => {
    // Attempt login through Zustand store
    await login(userCredObj);
    
    // We check the store's state after the async call
    // If no error was set by the store, it was a success
    if (!useAuth.getState().error) {
      toast.success("Logged in Successfully");
    }
  };

  // 2. Role-based Redirection
  useEffect(() => {
    if (isAuthenticated && currentUser) {
      if (currentUser.role === "USER") {
        navigate("/user-profile");
      } else if (currentUser.role === "AUTHOR") {
        navigate("/author-profile");
      }
    }
  }, [isAuthenticated, currentUser, navigate]);

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 p-4">
      <div className="w-full max-w-sm bg-white p-8 rounded-2xl shadow-xl border border-gray-200">
        <h2 className="text-3xl font-black text-center mb-8 text-gray-800">Login</h2>

        {/* Error display logic */}
  {error && (
    <div className="bg-red-50 border-l-4 border-red-500 p-3 mb-4 rounded shadow-sm animate-pulse">
      <div className="flex items-center">
        <svg className="w-4 h-4 text-red-500 mr-2" fill="currentColor" viewBox="0 0 20 20">
          <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
        </svg>
        <p className="text-red-700 text-xs font-black uppercase tracking-wider">
          {error}
        </p>
      </div>
    </div>
  )}

        <form onSubmit={handleSubmit(onLoginSubmit)}>
          
          {/* Email Input */}
          <div className="mb-4">
            <input 
              type="email" 
              {...register("email", { 
                required: "Email is required",
                pattern: {
                  value: /^\S+@\S+$/i,
                  message: "Please enter a valid email"
                }
              })} 
              placeholder="Email" 
              className={`w-full border-2 p-3 rounded-lg focus:outline-none transition-colors ${
                errors.email ? 'border-red-500 focus:border-red-500' : 'border-gray-200 focus:border-blue-400'
              }`} 
            />
            {errors.email && (
              <p className='text-red-600 text-[10px] font-black uppercase mt-1 ml-1 tracking-tight'>
                {errors.email.message}
              </p>
            )}
          </div>

          {/* Password Input */}
          <div className="mb-2">
            <input 
              type="password" 
              {...register("password", { 
                required: "Password is required",
                minLength: {
                  value: 4,
                  message: "Password must be at least 4 characters"
                }
              })} 
              placeholder="Password" 
              className={`w-full border-2 p-3 rounded-lg focus:outline-none transition-colors ${
                errors.password ? 'border-red-500 focus:border-red-500' : 'border-gray-200 focus:border-blue-400'
              }`} 
            />
            {errors.password && (
              <p className='text-red-600 text-[10px] font-black uppercase mt-1 ml-1 tracking-tight'>
                {errors.password.message}
              </p>
            )}
          </div>

          <p className="text-end text-xs text-gray-400 cursor-pointer hover:underline hover:text-blue-500 transition-all mb-6">
            Forgot password?
          </p>

          <button 
            type="submit" 
            disabled={loading}
            className="w-full py-3 bg-blue-600 hover:bg-blue-700 text-white font-bold rounded-xl shadow-md transition-all active:scale-95 disabled:bg-gray-300 disabled:cursor-not-allowed"
          >
            {loading ? "Authenticating..." : "Login"}
          </button>
        </form>
      </div>
    </div>
  );
}

export default Login;