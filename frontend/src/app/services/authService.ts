import fetchClient, { tokenManager } from "../lib/fetchClient";

import {
    LoginRequest,
    RegisterRequest,
    AuthResponse,
} from "../types/authTypes";

class AuthService {
  async login(data: LoginRequest): Promise<AuthResponse> {
    try {
      console.log("Attempting to log in with data:", data);
      console.log(
        "API Base URL:",
        process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:5262/api"
      );

      const response = await fetchClient.post<AuthResponse>(
        "/Auth/login",
        data
      );
      tokenManager.setToken(response.token);

      console.log("Successful login response:", response);
      localStorage.setItem("user", JSON.stringify(response.user));
      return response;
    } catch (error: any) {
      const errorMessage = error.message || "Login failed";
      throw new Error(errorMessage);
    }
  }

  getAccessToken(): string | null {
    return tokenManager.getToken();
  }

  async refreshToken(): Promise<void> {
    const response = await fetch(
      (process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:5262/api") + "/Auth/refresh",
      {
        method: "POST",
        credentials: "include",
      }
    );
    
    if (!response.ok) {
      throw new Error("Token refresh failed");
    }
    
    const data = await response.json();
    tokenManager.setToken(data.token);
  }

  logout(): void {
    tokenManager.clearToken();
    localStorage.removeItem("user");
    fetchClient.post("/Auth/logout");
  }

  async register(data: RegisterRequest): Promise<AuthResponse> {
    try {
      const response = await fetchClient.post<AuthResponse>(
        "/auth/register",
        data
      );

      console.log("Register response:", response);
      
      if (!response.token) {
        console.error("Response received but no token:", response);
        throw new Error("Token non reçu du serveur");
      }
      
      tokenManager.setToken(response.token);
      localStorage.setItem("user", JSON.stringify(response.user));
      return response;
    } catch (error: any) {
      console.error("Registration error:", error.message);
      const errorMessage = error.message || "Registration failed";
      throw new Error(errorMessage);
    }
  }
}

export default new AuthService();
