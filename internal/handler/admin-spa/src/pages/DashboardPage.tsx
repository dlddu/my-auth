import { useEffect, useState } from "react";
import { navigate } from "../App";

interface Stats {
  clients: number;
  active_sessions: number;
  tokens: number;
  auth_24h: number;
}

interface ActivityItem {
  time: string;
  action: string;
  client_name: string;
  type: string;
}

function formatDate(dateStr: string): string {
  if (!dateStr) return "";
  try {
    return new Date(dateStr).toLocaleString("ko-KR");
  } catch {
    return dateStr;
  }
}

const statConfig = [
  { key: "clients" as const, label: "클라이언트", color: "indigo" },
  { key: "active_sessions" as const, label: "활성 세션", color: "emerald" },
  { key: "tokens" as const, label: "토큰", color: "amber" },
  { key: "auth_24h" as const, label: "24h 인증", color: "sky" },
];

const colorMap: Record<string, { bg: string; border: string; label: string; value: string }> = {
  indigo: { bg: "rgba(49, 46, 129, 0.3)", border: "rgba(55, 48, 163, 0.5)", label: "#818cf8", value: "#e0e7ff" },
  emerald: { bg: "rgba(6, 78, 59, 0.3)", border: "rgba(6, 95, 70, 0.5)", label: "#34d399", value: "#d1fae5" },
  amber: { bg: "rgba(120, 53, 15, 0.3)", border: "rgba(146, 64, 14, 0.5)", label: "#fbbf24", value: "#fef3c7" },
  sky: { bg: "rgba(7, 89, 133, 0.3)", border: "rgba(7, 104, 159, 0.5)", label: "#38bdf8", value: "#e0f2fe" },
};

export default function DashboardPage() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [activity, setActivity] = useState<ActivityItem[] | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    async function load() {
      try {
        const [statsRes, activityRes] = await Promise.all([
          fetch("/api/admin/dashboard/stats", { credentials: "include" }),
          fetch("/api/admin/dashboard/activity", { credentials: "include" }),
        ]);

        if (statsRes.status === 401 || activityRes.status === 401) {
          navigate("/login");
          return;
        }

        if (!statsRes.ok || !activityRes.ok) {
          setError("데이터를 불러오는 중 오류가 발생했습니다.");
          return;
        }

        setStats(await statsRes.json());
        setActivity(await activityRes.json());
      } catch {
        setError("서버 연결에 실패했습니다.");
      }
    }
    load();
  }, []);

  if (error) {
    return (
      <div style={styles.alertError}>
        <p role="alert" style={{ color: "#f87171", textAlign: "center" }}>
          {error}
        </p>
      </div>
    );
  }

  return (
    <div>
      <header style={styles.header}>
        <div style={styles.headerInner}>
          <h1 style={styles.title}>MyAuth Admin</h1>
          <span style={styles.subtitle}>대시보드</span>
        </div>
      </header>

      <main style={styles.main}>
        <section aria-label="통계">
          <h2 style={styles.sectionTitle}>통계 개요</h2>
          <div style={styles.statGrid}>
            {statConfig.map(({ key, label, color }) => {
              const c = colorMap[color];
              return (
                <div
                  key={key}
                  aria-label={label}
                  style={{
                    borderRadius: "0.75rem",
                    padding: "1rem",
                    border: `1px solid ${c.border}`,
                    background: c.bg,
                  }}
                >
                  <span
                    style={{
                      fontSize: "0.75rem",
                      fontWeight: 500,
                      textTransform: "uppercase",
                      letterSpacing: "0.05em",
                      color: c.label,
                    }}
                  >
                    {label}
                  </span>
                  <span
                    style={{
                      display: "block",
                      fontSize: "1.875rem",
                      fontWeight: 700,
                      marginTop: "0.25rem",
                      color: c.value,
                    }}
                  >
                    {stats ? stats[key] : "—"}
                  </span>
                </div>
              );
            })}
          </div>
        </section>

        <section aria-label="최근 활동">
          <h2 style={styles.sectionTitle}>최근 활동</h2>
          <div style={styles.activityContainer}>
            {activity === null ? (
              <p style={styles.activityEmpty}>불러오는 중...</p>
            ) : activity.length === 0 ? (
              <ul role="list">
                <li style={styles.activityEmpty}>최근 활동이 없습니다.</li>
              </ul>
            ) : (
              <ul role="list" style={{ listStyle: "none", margin: 0, padding: 0 }}>
                {activity.map((item, i) => (
                  <li
                    key={i}
                    style={{
                      padding: "1rem 1.5rem",
                      borderBottom:
                        i < activity.length - 1
                          ? "1px solid #1f2937"
                          : "none",
                      display: "flex",
                      alignItems: "flex-start",
                      gap: "1rem",
                    }}
                  >
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <p
                        style={{
                          fontSize: "0.875rem",
                          fontWeight: 500,
                          color: "#fff",
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                          whiteSpace: "nowrap",
                          margin: 0,
                        }}
                      >
                        {item.client_name}
                      </p>
                      <p
                        style={{
                          fontSize: "0.75rem",
                          color: "#9ca3af",
                          marginTop: "0.125rem",
                          margin: 0,
                        }}
                      >
                        {item.action} · {item.type}
                      </p>
                    </div>
                    <time
                      style={{
                        fontSize: "0.75rem",
                        color: "#6b7280",
                        whiteSpace: "nowrap",
                        marginTop: "0.125rem",
                      }}
                    >
                      {formatDate(item.time)}
                    </time>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </section>
      </main>
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  header: {
    background: "#111827",
    borderBottom: "1px solid #1f2937",
    padding: "1rem 1.5rem",
  },
  headerInner: {
    maxWidth: "56rem",
    margin: "0 auto",
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
  },
  title: { fontSize: "1.25rem", fontWeight: 700, color: "#fff", margin: 0 },
  subtitle: { fontSize: "0.875rem", color: "#9ca3af" },
  main: { maxWidth: "56rem", margin: "0 auto", padding: "2rem 1.5rem" },
  sectionTitle: {
    fontSize: "1.125rem",
    fontWeight: 600,
    color: "#e5e7eb",
    marginBottom: "1rem",
  },
  statGrid: {
    display: "grid",
    gridTemplateColumns: "repeat(2, 1fr)",
    gap: "1rem",
    marginBottom: "2rem",
  },
  activityContainer: {
    background: "#111827",
    borderRadius: "0.75rem",
    border: "1px solid #1f2937",
    overflow: "hidden",
  },
  activityEmpty: {
    padding: "1.5rem",
    textAlign: "center",
    color: "#6b7280",
    fontSize: "0.875rem",
    margin: 0,
  },
  alertError: {
    minHeight: "100vh",
    background: "#030712",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
  },
};
