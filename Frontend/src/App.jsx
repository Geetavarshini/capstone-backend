import React from 'react'
import { createBrowserRouter, RouterProvider } from 'react-router'
import RootLayout from './components/RootLayout'
import Register from './components/Register'
import Home from './components/Home'
import Login from './components/Login'
import UserProfile from './components/UserProfile'
import AuthorProfile from './components/AuthorProfile'
import { Toaster } from 'react-hot-toast'
import AddArticle from './components/AddArticle'
import ProtectedRoute from './components/ProtectedRoute'
// Import the new ArticleDetail component
import ArticleDetail from './components/ArticleDetail' 
import { useEffect } from 'react'
import { useAuth } from './AuthStore/useAuth'
import ErrorBoundary from './components/ErrorBoundary'

const routerObject = createBrowserRouter([
  {
    path: "/",
    element: <RootLayout />,
    errorElement: <ErrorBoundary />, // Global error boundary for all child routes
    children: [
      {
        path: "",
        element: <Home />
      },
      {
        path: "register",
        element: <Register />
      },
      {
        path: "login",
        element: <Login />
      },
      {
        path: "user-profile",
        element: <ProtectedRoute allowedRoles={["USER"]}><UserProfile /></ProtectedRoute>
      },
      {
        path: "article/:id",
        element: <ProtectedRoute allowedRoles={["USER", "AUTHOR"]}><ArticleDetail /></ProtectedRoute>
      },
      {
        path: "author-profile",
        element: <ProtectedRoute allowedRoles={["AUTHOR"]}><AuthorProfile /></ProtectedRoute>,
      },
      {
        path: "add-article",
        element: <ProtectedRoute allowedRoles={["AUTHOR"]}><AddArticle /></ProtectedRoute>
      }
    ]
  }
])

function App() {
  const { checkAuth } = useAuth();

    

  useEffect(() => {
    checkAuth(); // runs on every refresh to validate session
  }, []);

  return (
    <>
      <Toaster position="top-center" reverseOrder={false} />
      <RouterProvider router={routerObject} />
    </>
  )
}

export default App