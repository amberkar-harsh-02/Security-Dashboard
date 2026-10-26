import { BrowserRouter, Navigate, Route, Routes, useLocation } from "react-router";
import { AuthProvider, useAuth } from "./auth/AuthProvider";
import AppShell from "./components/AppShell";
import { LiveProvider } from "./hooks/useLive";
import { TimeRangeProvider } from "./hooks/useTimeRange";
import AlertDetail from "./pages/AlertDetail";
import Blocked from "./pages/Blocked";
import Alerts from "./pages/Alerts";
import Events from "./pages/Events";
import Overview from "./pages/Overview";
import Performance from "./pages/Performance";
import { NotFound } from "./pages/NotFound";
import Rules from "./pages/Rules";
import SignIn from "./pages/SignIn";
import Sources from "./pages/Sources";

function RequireSignIn({ children }) {
  const { status } = useAuth();
  const location = useLocation();
  if (status === "loading") {
    return (
      <p className="visually-hidden" role="status">
        Loading
      </p>
    );
  }
  if (status === "signed-out") {
    return <Navigate to="/signin" replace state={{ from: location.pathname + location.search }} />;
  }
  return children;
}

function SignedInApp() {
  return (
    <TimeRangeProvider>
      <LiveProvider>
        <AppShell />
      </LiveProvider>
    </TimeRangeProvider>
  );
}

export function AppRoutes() {
  return (
    <Routes>
      <Route path="/signin" element={<SignIn />} />
      <Route
        element={
          <RequireSignIn>
            <SignedInApp />
          </RequireSignIn>
        }
      >
        <Route index element={<Overview />} />
        <Route path="alerts" element={<Alerts />} />
        <Route path="alerts/:id" element={<AlertDetail />} />
        <Route path="events" element={<Events />} />
        <Route path="rules" element={<Rules />} />
        <Route path="sources" element={<Sources />} />
        <Route path="blocked" element={<Blocked />} />
        <Route path="performance" element={<Performance />} />
        <Route path="*" element={<NotFound />} />
      </Route>
    </Routes>
  );
}

export default function App() {
  return (
    <BrowserRouter basename={import.meta.env.BASE_URL.replace(/\/$/, "")}>
      <AuthProvider>
        <AppRoutes />
      </AuthProvider>
    </BrowserRouter>
  );
}
