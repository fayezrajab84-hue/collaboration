import { Routes, Route, Navigate } from "react-router-dom";
import { useAuth } from "./hooks/useAuth";
import Layout from "./components/Layout";
import LoginPage from "./pages/LoginPage";
import DashboardPage from "./pages/DashboardPage";
import RepositoriesPage from "./pages/RepositoriesPage";
import ContainersPage from "./pages/ContainersPage";
import DomainsPage from "./pages/DomainsPage";
import FindingsPage from "./pages/FindingsPage";
import TicketsPage from "./pages/TicketsPage";
import SettingsPage from "./pages/SettingsPage";

function AuthGuard({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="flex h-screen items-center justify-center bg-gray-950">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-indigo-500 border-t-transparent" />
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return <>{children}</>;
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        path="/"
        element={
          <AuthGuard>
            <Layout />
          </AuthGuard>
        }
      >
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="dashboard" element={<DashboardPage />} />
        <Route path="repositories" element={<RepositoriesPage />} />
        <Route path="containers" element={<ContainersPage />} />
        <Route path="domains" element={<DomainsPage />} />
        <Route path="findings" element={<FindingsPage />} />
        <Route path="tickets" element={<TicketsPage />} />
        <Route path="settings" element={<SettingsPage />} />
      </Route>
      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  );
}
