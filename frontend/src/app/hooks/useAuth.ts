import { useState, useEffect, useCallback } from "react";
import authService from "../services/authService";
import userService from "../services/userService";
import { LoginRequest, RegisterRequest } from "../types/authTypes";
import { MyUserProfile, BaseUser } from "../types/userTypes";
import { useRouter } from "next/navigation";

export function useAuth() {
    const [user, setUser] = useState<BaseUser | null>(null);
    const [loading, setLoading] = useState<boolean>(true);
    const [error, setError] = useState<string | null>(null);
    const router = useRouter();

    useEffect(() => {
        const loadUser = async () => {
            try {
                // Tenter de rafraîchir le token via le cookie HttpOnly
                await authService.refreshToken();
                // Token valide - récupérer les infos utilisateur depuis l'API
                const profile = await userService.getMyProfile();
                setUser(profile);
            } catch {
                // Pas de session valide, l'utilisateur n'est pas connecté
            } finally {
                setLoading(false);
            }
        };
        loadUser();
    }, []);

    const login = async (data: LoginRequest) => {
        try {
            setLoading(true);
            setError(null);
            await authService.login(data);
            // Récupérer les infos utilisateur après login
            const profile = await userService.getMyProfile();
            setUser(profile);
            router.push("/dashboard");
        } catch (error) {
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
            await authService.register(data);
            // Récupérer les infos utilisateur après inscription
            const profile = await userService.getMyProfile();
            setUser(profile);
            router.push("/dashboard");
        } catch (error) {
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

    const fetchProfile = useCallback(async (): Promise<MyUserProfile | null> => {
        try {
            const profile = await userService.getMyProfile();
            return profile;
        } catch (error) {
            setError("Failed to fetch profile");
            return null;
        }
    }, []);

    return { user, loading, error, login, register, logout, fetchProfile }
}