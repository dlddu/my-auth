import { FormEvent, useState } from "react";
import { navigate } from "../App";

export default function LoginPage() {
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError("");
    setLoading(true);

    const form = e.currentTarget;
    const username = (form.elements.namedItem("username") as HTMLInputElement)
      .value;
    const password = (form.elements.namedItem("password") as HTMLInputElement)
      .value;

    try {
      const res = await fetch("/api/admin/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ username, password }),
      });

      if (res.ok) {
        navigate("/");
      } else {
        let errorMsg = "인증 실패: 아이디 또는 비밀번호가 잘못되었습니다.";
        try {
          const data = await res.json();
          if (data.error) errorMsg = data.error;
        } catch {
          /* ignore parse error */
        }
        setError(errorMsg);
        setLoading(false);
      }
    } catch {
      setError("서버 연결에 실패했습니다. 잠시 후 다시 시도해주세요.");
      setLoading(false);
    }
  }

  return (
    <div style={styles.wrapper}>
      <div style={styles.card}>
        <h1 role="heading" aria-level={1} style={styles.heading}>
          MyAuth Admin
        </h1>
        <p style={styles.subtitle}>관리자 포털에 로그인하세요</p>

        {error && (
          <div role="alert" style={styles.errorBanner}>
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit}>
          <div style={styles.formGroup}>
            <label htmlFor="username" style={styles.label}>
              아이디
            </label>
            <input
              id="username"
              type="text"
              placeholder="admin"
              required
              autoComplete="username"
              style={styles.input}
            />
          </div>

          <div style={styles.formGroup}>
            <label htmlFor="password" style={styles.label}>
              비밀번호
            </label>
            <input
              id="password"
              type="password"
              placeholder="••••••••"
              required
              autoComplete="current-password"
              style={styles.input}
            />
          </div>

          <button
            type="submit"
            role="button"
            disabled={loading}
            style={{
              ...styles.button,
              ...(loading ? styles.buttonDisabled : {}),
            }}
          >
            {loading ? "로그인 중..." : "관리자 로그인"}
          </button>
        </form>
      </div>
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  wrapper: {
    minHeight: "100vh",
    background: "#030712",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    padding: "1rem",
  },
  card: {
    width: "100%",
    maxWidth: 380,
    background: "#111827",
    borderRadius: "1rem",
    boxShadow: "0 25px 50px rgba(0,0,0,0.5)",
    padding: "2rem",
  },
  heading: {
    fontSize: "1.5rem",
    fontWeight: 700,
    color: "#fff",
    textAlign: "center",
    marginBottom: "0.5rem",
  },
  subtitle: {
    fontSize: "0.875rem",
    color: "#9ca3af",
    textAlign: "center",
    marginBottom: "2rem",
  },
  errorBanner: {
    marginBottom: "1rem",
    background: "rgba(127, 29, 29, 0.5)",
    border: "1px solid #b91c1c",
    color: "#fca5a5",
    borderRadius: "0.5rem",
    padding: "0.75rem 1rem",
    fontSize: "0.875rem",
  },
  formGroup: { marginBottom: "1rem" },
  label: {
    display: "block",
    fontSize: "0.875rem",
    fontWeight: 500,
    color: "#d1d5db",
    marginBottom: "0.25rem",
  },
  input: {
    width: "100%",
    background: "#1f2937",
    color: "#fff",
    border: "1px solid #374151",
    borderRadius: "0.5rem",
    padding: "0.75rem 1rem",
    fontSize: "0.875rem",
    outline: "none",
    boxSizing: "border-box",
  },
  button: {
    width: "100%",
    background: "#4f46e5",
    color: "#fff",
    fontWeight: 600,
    border: "none",
    borderRadius: "0.5rem",
    padding: "0.75rem 1rem",
    fontSize: "0.875rem",
    cursor: "pointer",
    marginTop: "0.5rem",
  },
  buttonDisabled: {
    background: "#3730a3",
    cursor: "not-allowed",
  },
};
