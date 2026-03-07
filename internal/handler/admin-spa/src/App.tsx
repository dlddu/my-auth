import { useEffect, useState } from "react";
import LoginPage from "./pages/LoginPage";
import DashboardPage from "./pages/DashboardPage";

const BASE = "/admin";

function getPath(): string {
  const p = window.location.pathname;
  if (p === BASE || p === BASE + "/") return "/";
  if (p.startsWith(BASE + "/")) return p.slice(BASE.length);
  return p || "/";
}

export function navigate(path: string) {
  const dest = path === "/" ? BASE : BASE + path;
  window.history.pushState({}, "", dest);
  window.dispatchEvent(new PopStateEvent("popstate"));
}

export default function App() {
  const [path, setPath] = useState(getPath);

  useEffect(() => {
    const onPopState = () => setPath(getPath());
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  if (path === "/login") {
    return <LoginPage />;
  }
  return <DashboardPage />;
}
