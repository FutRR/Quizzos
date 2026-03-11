import fetchClient, { tokenManager } from "../lib/fetchClient";

import {
    LoginRequest,
    RegisterRequest,
} from "../types/authTypes";

class AuthService {
  async login(data: LoginRequest): Promise<{ token: string }> {
    try {
      const response = await fetchClient.post<{ token: string }>(
        "/Auth/login",
        data
      );
      tokenManager.setToken(response.token);
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
    const response = await fetchClient.post<{ token: string }>(
      "/Auth/refresh"
    );
    tokenManager.setToken(response.token);
  }

  logout(): void {
    tokenManager.clearToken();
    fetchClient.post("/Auth/logout");
  }

  async register(data: RegisterRequest): Promise<{ token: string }> {
    try {
      const response = await fetchClient.post<{ token: string }>(
        "/Auth/register",
        data
      );

      if (!response.token) {
        throw new Error("Token non reçu du serveur");
      }
      
      tokenManager.setToken(response.token);
      return response;
    } catch (error: any) {
      const errorMessage = error.message || "Registration failed";
      throw new Error(errorMessage);
    }
  }
}

export default new AuthService();
