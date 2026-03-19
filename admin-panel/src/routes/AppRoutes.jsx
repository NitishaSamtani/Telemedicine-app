import { Routes, Route, Navigate, Outlet } from "react-router-dom";
import { useEffect } from "react";
import AdminRoutes from "./AdminRoutes";

// 🌍 External Redirect Component
const ExternalRedirect = ({ to }) => {
  useEffect(() => {
    window.location.href = to;
  }, [to]);

  return null;
};

// 🔐 Protect admin routes
const AdminRoute = () => {
  const role = localStorage.getItem("role");

  return role === "admin" ? (
    <Outlet />
  ) : (
    <ExternalRedirect to="http://localhost:5173/login" />
  );
};

const AppRoutes = () => {
  const role = localStorage.getItem("role");

  return (
    <Routes>
      {/* Root route */}
      <Route
        path="/"
        element={
          role === "admin" ? (
            <Navigate to="/admin/dashboard" replace />
          ) : (
            <ExternalRedirect to="http://localhost:5173/login" />
          )
        }
      />

      {/* Protected admin routes */}
      <Route element={<AdminRoute />}>
        <Route path="/admin/*" element={<AdminRoutes />} />
      </Route>

      {/* Catch all */}
      <Route
        path="*"
        element={<ExternalRedirect to="http://localhost:5173/login" />}
      />
    </Routes>
  );
};

export default AppRoutes;