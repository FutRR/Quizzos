import { useState, useEffect } from "react";
import authService from "../services/authService";
import userService from "../services/userService";
import { User, LoginRequest, RegisterRequest } from "../types/authTypes";
import { MyUserProfile } from "../types/userTypes";
import { useRouter } from "next/navigation";

export function useAuth() {
    console.log("[useAuth] Hook called");
    const [user, setUser] = useState<User | null>(null);
    const [loading, setLoading] = useState<boolean>(true);
    const [error, setError] = useState<string | null>(null);
    const router = useRouter();

    useEffect(() => {
        console.log("[useAuth] useEffect triggered - checking session");
        const loadUser = async () => {
            try {
                const storedUser = localStorage.getItem("user");
                console.log("[useAuth] Stored user from localStorage:", storedUser);
                
                if (storedUser && storedUser !== "undefined" && storedUser !== "null") {
                    // Utilisateur stocké - tenter de rafraîchir le token via cookie HttpOnly
                    console.log("[useAuth] User found in localStorage - attempting token refresh...");
                    try {
                        await authService.refreshToken();
                        const parsedUser = JSON.parse(storedUser);
                        console.log("[useAuth] Token refreshed successfully, user:", parsedUser);
                        setUser(parsedUser);
                    } catch (refreshError) {
                        console.log("[useAuth] Token refresh failed - session expired");
                        localStorage.removeItem("user");
                    }
                } else {
                    console.log("[useAuth] No stored user - not logged in");
                }
            } catch (error) {
                console.error("[useAuth] Error loading user:", error);
                localStorage.removeItem("user");
            } finally {
                console.log("[useAuth] loadUser completed - setting loading to false");
                setLoading(false);
            }
        };
        loadUser();
    }, []);

    const login = async (data: LoginRequest) => {
        try {
            setLoading(true);
            setError(null);
            console.log("[useAuth] Calling authService.login()...");
            const response = await authService.login(data);
            console.log("[useAuth] Login response received:", response);
            setUser(response.user);
            router.push("/dashboard");
        } catch (error) {
            console.error("[useAuth] Login error:", error);
            setError("Login failed");
            throw error;
        } finally {
            setLoading(false);
        }
    }

    const register = async (data: RegisterRequest) => {
        try {
            setLoading(true);
            setError(null);
            console.log("[useAuth] Calling authService.register()...");
            const response = await authService.register(data);
            console.log("[useAuth] Register response received:", response);
            setUser(response.user);
            router.push("/dashboard");
        } catch (error) {
            console.error("[useAuth] Registration error:", error);
            setError("Registration failed");
            throw error;
        } finally {
            setLoading(false);
        }
    }

    const logout = () => {
        authService.logout();
        setUser(null);
        router.push("/login");
    }

    const fetchProfile = async (): Promise<MyUserProfile | null> => {
        console.log("[useAuth] fetchProfile() called");
        try {
            console.log("[useAuth] Calling userService.getMyProfile()...");
            const profile = await userService.getMyProfile();
            console.log("[useAuth] Profile received from userService:", profile);
            return profile;
        } catch (error) {
            console.error("[useAuth] Error fetching profile:", error);
            setError("Failed to fetch profile");
            return null;
        }
    }

    return { user, loading, error, login, register, logout, fetchProfile }
}