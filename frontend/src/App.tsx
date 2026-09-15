import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { AuthProvider, useAuth } from "./core/auth";
import { Layout } from "./core/Layout";
import { LoginPage } from "./core/LoginPage";
import { enabledRoutes } from "./featureManifest";

export function App({ fetchImpl }: { fetchImpl?: typeof fetch }) {
  return (
    <AuthProvider fetchImpl={fetchImpl}>
      <BrowserRouter>
        <Shell />
      </BrowserRouter>
    </AuthProvider>
  );
}

function Shell() {
  const { principal } = useAuth();
  if (!principal) {
    return <LoginPage />;
  }
  const routes = enabledRoutes(principal.features);
  return (
    <Routes>
      <Route element={<Layout />}>
        {routes.map(({ path, Component }) => (
          <Route key={path} path={path} element={<Component />} />
        ))}
        <Route path="*" element={<Navigate to="/overview" replace />} />
      </Route>
    </Routes>
  );
}
