import { useRouteError, useNavigate } from "react-router";

function ErrorBoundary() {
  const error = useRouteError();
  const navigate = useNavigate();

  // Handle cases where error might not have the expected properties
  const status = error?.status || "Error";
  const statusText = error?.statusText || "Something went wrong";
  const data = error?.data || "We couldn't find the page you're looking for.";

  return (
    <div className="min-h-[80vh] flex flex-col items-center justify-center text-center px-4 py-20">
      {/* Visual Indicator */}
      <div className="relative mb-10">
        <img 
          className="block mx-auto rounded-3xl w-full max-w-lg shadow-2xl border-4 border-white" 
          src="https://media.tenor.com/WqGTNFmFqjkAAAAM/saquontroll-saquonjudge26.gif" 
          alt="Error Illustration" 
        />
        <div className="absolute -bottom-4 left-1/2 -translate-x-1/2 bg-red-500 text-white px-6 py-1 rounded-full font-black tracking-widest text-xl shadow-lg">
          {status}
        </div>
      </div>

      {/* Error Details */}
      <h1 className="text-4xl md:text-5xl font-extrabold text-gray-900 mb-4">
        {statusText}
      </h1>
      
      <p className="text-lg text-gray-500 max-w-md mx-auto mb-10 leading-relaxed">
        {typeof data === 'string' ? data : "An unexpected error occurred while processing your request."}
      </p>

      {/* Action Button */}
      <button 
        onClick={() => navigate("/")}
        className="px-8 py-3 bg-indigo-600 hover:bg-indigo-700 text-white font-bold rounded-xl shadow-lg shadow-indigo-100 transition-all transform active:scale-95"
      >
        Take Me Home
      </button>
    </div>
  );
}

export default ErrorBoundary;