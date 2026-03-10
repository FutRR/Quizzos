const API_BASE = process.env.NEXT_PUBLIC_API_URL || "https://localhost:7xxx";

export async function login(username: string, password: string, audience: string) {
  const res = await fetch(`${API_BASE}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include", // pour envoyer/recevoir les cookies
    body: JSON.stringify({ username, password, audience }),
  });
  return res;
}

export async function getMyProfile(token: string) {
  const res = await fetch(`${API_BASE}/api/user/me`, {
    headers: { Authorization: `Bearer ${token}` },
    credentials: "include",
  });
  return res;
}