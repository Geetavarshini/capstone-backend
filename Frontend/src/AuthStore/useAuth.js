import axios from "axios";
import { create } from "zustand";
import { persist } from "zustand/middleware"; // 1. Import persist middleware

const BASE_URL = "https://capstone-project-rbl1.onrender.com";
export const useAuth = create(
  persist(
    (set) => ({
      currentUser: null,
      loading: false,
      error: null,
      isAuthenticated: false,

      // LOGIN LOGIC
      login: async (userCredWithRole) => {
        let { role, ...userCredObj } = userCredWithRole;
        try {
          set({ loading: true, error: null });
          let res = await axios.post(
            `${BASE_URL}/common-api/authenticate`,
            userCredObj,
            { withCredentials: true }
          );
          set({
            loading: false,
            isAuthenticated: true,
            currentUser: res.data.payload,
          });
        } catch (err) {
          set({
            loading: false,
            isAuthenticated: false,
            currentUser: null,
            error: err.response?.data?.message || "Login failed",
          });
        }
      },

      // LOGOUT LOGIC
      logout: async () => {
        try {
          set({ loading: true, error: null });
          await axios.get(`${BASE_URL}/common-api/logout`, {
            withCredentials: true,
          });
          set({
            loading: false,
            isAuthenticated: false,
            currentUser: null,
          });
          localStorage.removeItem("user-auth-storage");
        } catch (err) {
          set({
            loading: false,
            error: err.response?.data?.message || "Logout failed",
          });
        }
      },

      // SESSION CHECK
      checkAuth: async () => {
        set({ loading: true });
        try {
          let res = await axios.get(`${BASE_URL}/common-api/check-auth`, {
            withCredentials: true,
          });
          set({
            loading: false,
            isAuthenticated: true,
            currentUser: res.data.payload,
          });
        } catch (err) {
          set({
            loading: false,
            isAuthenticated: false,
            currentUser: null,
            error: null,
          });
        }
      },
    }),
    {
      name: "user-auth-storage",
      partialize: (state) => ({
        currentUser: state.currentUser,
        isAuthenticated: state.isAuthenticated,
      }),
    }
  )
);