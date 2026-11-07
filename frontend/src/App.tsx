import { lazy, Suspense } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { Spin } from "antd";
import Layout from "./components/Layout";
import ErrorBoundary from "./components/ErrorBoundary";
import { RequireAuth, RequireRole } from "./components/AuthGuard";
import { AuthProvider, hasRole, useAuth } from "./auth";

// 路由按 code-split：首屏只加载 Layout + Dashboard
const DashboardPage = lazy(() => import("./pages/DashboardPage"));
const TicketsPage = lazy(() => import("./pages/TicketsPage"));
const NewTicketPage = lazy(() => import("./pages/NewTicketPage"));
const TicketDetailPage = lazy(() => import("./pages/TicketDetailPage"));
const InventoryPage = lazy(() => import("./pages/InventoryPage"));
const SyncPage = lazy(() => import("./pages/SyncPage"));
const AccountAdminPage = lazy(() => import("./pages/AccountAdminPage"));
const AuditPage = lazy(() => import("./pages/AuditPage"));
const CleanupPage = lazy(() => import("./pages/CleanupPage"));
const BaselinePage = lazy(() => import("./pages/BaselinePage"));
const DriftPage = lazy(() => import("./pages/DriftPage"));
const UsersPage = lazy(() => import("./pages/UsersPage"));
const LoginPage = lazy(() => import("./pages/LoginPage"));

function PageLoading() {
  return (
    <div style={{ display: "flex", justifyContent: "center", padding: 80 }}>
      <Spin size="large" />
    </div>
  );
}

function HomePage() {
  const { user } = useAuth();
  if (!hasRole(user, "platform_admin", "approval_admin")) {
    return <Navigate to="/tickets" replace />;
  }
  return (
    <Suspense fallback={<PageLoading />}>
      <DashboardPage />
    </Suspense>
  );
}

export default function App() {
  return (
    <ErrorBoundary>
      <AuthProvider>
        <Routes>
          <Route
            path="/login"
            element={
              <Suspense fallback={<PageLoading />}>
                <LoginPage />
              </Suspense>
            }
          />
          <Route
            element={
              <RequireAuth>
                <Layout />
              </RequireAuth>
            }
          >
            <Route index element={<HomePage />} />
            <Route
              path="tickets"
              element={
                <Suspense fallback={<PageLoading />}>
                  <TicketsPage />
                </Suspense>
              }
            />
            <Route
              path="tickets/new"
              element={
                <Suspense fallback={<PageLoading />}>
                  <NewTicketPage />
                </Suspense>
              }
            />
            <Route
              path="tickets/:ticketNo"
              element={
                <Suspense fallback={<PageLoading />}>
                  <TicketDetailPage />
                </Suspense>
              }
            />
            <Route
              path="inventory"
              element={
                <Suspense fallback={<PageLoading />}>
                  <InventoryPage />
                </Suspense>
              }
            />
            <Route
              path="sync"
              element={
                <Suspense fallback={<PageLoading />}>
                  <SyncPage />
                </Suspense>
              }
            />
            <Route
              path="accounts"
              element={
                <RequireRole roles={["platform_admin"]}>
                  <Suspense fallback={<PageLoading />}>
                    <AccountAdminPage />
                  </Suspense>
                </RequireRole>
              }
            />
            <Route
              path="audit"
              element={
                <RequireRole roles={["platform_admin"]}>
                  <Suspense fallback={<PageLoading />}>
                    <AuditPage />
                  </Suspense>
                </RequireRole>
              }
            />
            <Route
              path="cleanup"
              element={
                <RequireRole roles={["platform_admin"]}>
                  <Suspense fallback={<PageLoading />}>
                    <CleanupPage />
                  </Suspense>
                </RequireRole>
              }
            />
            <Route
              path="baseline"
              element={
                <RequireRole roles={["platform_admin"]}>
                  <Suspense fallback={<PageLoading />}>
                    <BaselinePage />
                  </Suspense>
                </RequireRole>
              }
            />
            <Route
              path="drift"
              element={
                <Suspense fallback={<PageLoading />}>
                  <DriftPage />
                </Suspense>
              }
            />
            <Route
              path="users"
              element={
                <RequireRole roles={["platform_admin"]}>
                  <Suspense fallback={<PageLoading />}>
                    <UsersPage />
                  </Suspense>
                </RequireRole>
              }
            />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
      </AuthProvider>
    </ErrorBoundary>
  );
}
