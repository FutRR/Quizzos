// Configuration de base pour fetch
const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:5134/api";

interface FetchOptions extends RequestInit {
  timeout?: number;
  _retried?: boolean;
}

// Gestionnaire de token centralisé
let accessToken: string | null = null;
let isRefreshing = false;
let refreshPromise: Promise<void> | null = null;

export const tokenManager = {
  getToken: () => accessToken,
  setToken: (token: string | null) => { accessToken = token; },
  clearToken: () => { accessToken = null; },
};

class FetchClient {
  private baseURL: string;
  private defaultTimeout: number;

  constructor(baseURL: string, timeout: number = 5000) {
    this.baseURL = baseURL;
    this.defaultTimeout = timeout;
  }

  // Tenter de rafraîchir le token via le cookie HttpOnly
  private async tryRefreshToken(): Promise<boolean> {
    if (isRefreshing) {
      await refreshPromise;
      return tokenManager.getToken() !== null;
    }

    isRefreshing = true;
    refreshPromise = (async () => {
      try {
        const response = await fetch(`${this.baseURL}/Auth/refresh`, {
          method: "POST",
          credentials: "include",
          headers: { "Content-Type": "application/json" },
        });

        if (response.ok) {
          const data = await response.json();
          tokenManager.setToken(data.token);
        } else {
          tokenManager.clearToken();
        }
      } catch {
        tokenManager.clearToken();
      } finally {
        isRefreshing = false;
        refreshPromise = null;
      }
    })();

    await refreshPromise;
    return tokenManager.getToken() !== null;
  }

  private async request<T>(
    endpoint: string,
    options: FetchOptions = {}
  ): Promise<T> {
    const { timeout = this.defaultTimeout, ...fetchOptions } = options;

    // Ajouter le token d'authentification depuis la mémoire
    const token = tokenManager.getToken();
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      ...(fetchOptions.headers as Record<string, string>),
    };

    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }


    const csrfToken = typeof document !== "undefined"
      ? document.cookie
          .split("; ")
          .find((row) => row.startsWith("XSRF-TOKEN="))
          ?.split("=")[1]
      : undefined;

    // Ajouter le header CSRF si disponible
    // const csrfToken = document.cookie
    //   .split("; ")
    //   .find((row) => row.startsWith("XSRF-TOKEN="))
    //   ?.split("=")[1];
    // if (csrfToken) {
    //   headers["X-CSRF-Token"] = csrfToken;
    // }
    

    // Créer un AbortController pour le timeout
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    try {
      const response = await fetch(`${this.baseURL}${endpoint}`, {
        ...fetchOptions,
        headers,
        credentials: "include",
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      // Gérer les erreurs 401 - tenter un refresh du token (une seule fois)
      if (response.status === 401 && !endpoint.includes("/Auth/") && !options._retried) {
        const refreshed = await this.tryRefreshToken();
        if (refreshed) {
          // Réessayer la requête avec le nouveau token (marqué comme retry)
          return this.request<T>(endpoint, { ...options, _retried: true });
        }
        tokenManager.clearToken();
        window.location.href = "/login";
        throw new Error("Unauthorized");
      }

      // Vérifier si la réponse est OK
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        // Gérer les erreurs Identity (tableau d'objets avec code/description)
        if (Array.isArray(errorData)) {
          const messages = errorData.map((e: any) => e.description || e.code).join(", ");
          throw new Error(messages || `HTTP error! status: ${response.status}`);
        }
        throw new Error(
          errorData.error || errorData.message || errorData.title || `HTTP error! status: ${response.status}`
        );
      }

      // Gérer les réponses vides (204 No Content ou body vide)
      const text = await response.text();
      if (!text) {
        return {} as T;
      }
      return JSON.parse(text);
    } catch (error: any) {
      if (error.name === "AbortError") {
        throw new Error("Request timeout");
      }
      throw error;
    }
  }

  async get<T>(endpoint: string, options?: FetchOptions): Promise<T> {
    return this.request<T>(endpoint, { ...options, method: "GET" });
  }

  async post<T>(
    endpoint: string,
    data?: any,
    options?: FetchOptions
  ): Promise<T> {
    return this.request<T>(endpoint, {
      ...options,
      method: "POST",
      body: JSON.stringify(data),
    });
  }

  async put<T>(
    endpoint: string,
    data?: any,
    options?: FetchOptions
  ): Promise<T> {
    return this.request<T>(endpoint, {
      ...options,
      method: "PUT",
      body: JSON.stringify(data),
    });
  }

  async delete<T>(endpoint: string, options?: FetchOptions): Promise<T> {
    return this.request<T>(endpoint, { ...options, method: "DELETE" });
  }

  async patch<T>(
    endpoint: string,
    data?: any,
    options?: FetchOptions
  ): Promise<T> {
    return this.request<T>(endpoint, {
      ...options,
      method: "PATCH",
      body: JSON.stringify(data),
    });
  }

  // Méthode pour envoyer des FormData (upload de fichiers)
  // Ne pas définir Content-Type : le navigateur le fait automatiquement avec le boundary
  async postFormData<T>(
    endpoint: string,
    formData: FormData,
    options?: FetchOptions
  ): Promise<T> {
    const { timeout = this.defaultTimeout, ...fetchOptions } = options || {};

    // Récupérer le token d'authentification depuis la mémoire
    const token = tokenManager.getToken();
    const headers: Record<string, string> = {};

    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }

    // Créer un AbortController pour le timeout
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    try {
      const response = await fetch(`${this.baseURL}${endpoint}`, {
        ...fetchOptions,
        method: "POST",
        headers,
        body: formData, // FormData directement, pas de JSON.stringify
        credentials: "include",
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (response.status === 401) {
        const refreshed = await this.tryRefreshToken();
        if (refreshed) {
          return this.postFormData<T>(endpoint, formData, options);
        }
        tokenManager.clearToken();
        window.location.href = "/login";
        throw new Error("Unauthorized");
      }

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(
          errorData.message || `HTTP error! status: ${response.status}`
        );
      }

      return await response.json();
    } catch (error: any) {
      if (error.name === "AbortError") {
        throw new Error("Request timeout");
      }
      throw error;
    }
  }
}

export const fetchClient = new FetchClient(API_BASE_URL);
export default fetchClient;
