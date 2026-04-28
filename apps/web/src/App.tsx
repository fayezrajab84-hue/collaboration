import { Routes, Route, Navigate } from "react-router-dom";
import { useAuth } from "./hooks/useAuth";
import { ToastProvider } from "./hooks/useToast";
import Layout from "./components/Layout";
import LoginPage from "./pages/LoginPage";
import DashboardPage from "./pages/DashboardPage";
import RepositoriesPage from "./pages/RepositoriesPage";
import ContainersPage from "./pages/ContainersPage";
import DomainsPage from "./pages/DomainsPage";
import DomainDetailPage from "./pages/DomainDetailPage";
import FindingsPage from "./pages/FindingsPage";
import TicketsPage from "./pages/TicketsPage";
import ScansPage from "./pages/ScansPage";
import SettingsPage from "./pages/SettingsPage";
import ChatPage from "./pages/ChatPage";
import ReportPage from "./pages/ReportPage";
import AdminQueuesPage from "./pages/AdminQueuesPage";
import CompliancePage from "./pages/CompliancePage";
import AttackPathsPage from "./pages/AttackPathsPage";
import ApplicationsPage from "./pages/ApplicationsPage";
import RuntimePage from "./pages/RuntimePage";

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
    <ToastProvider>
      <AppRoutes />
    </ToastProvider>
  );
}

function AppRoutes() {
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
        <Route path="domains/:id" element={<DomainDetailPage />} />
        <Route path="runtime" element={<RuntimePage />} />
        <Route path="scans" element={<ScansPage />} />
        <Route path="findings" element={<FindingsPage />} />
        <Route path="tickets" element={<TicketsPage />} />
        <Route path="settings" element={<SettingsPage />} />
        <Route path="chat" element={<ChatPage />} />
        <Route path="report" element={<ReportPage />} />
        <Route path="compliance" element={<CompliancePage />} />
        <Route path="attack-paths" element={<AttackPathsPage />} />
        <Route path="attack-paths/:groupId" element={<AttackPathsPage />} />
        <Route path="applications" element={<ApplicationsPage />} />
        <Route path="applications/:id" element={<ApplicationsPage />} />
        <Route path="admin/queues" element={<AdminQueuesPage />} />
      </Route>
      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  );
}
