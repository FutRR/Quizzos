import { useState, useEffect, useCallback, useContext, createContext, ReactNode } from "react";
import authService from "../services/authService";
import userService from "../services/userService";
import { LoginRequest, RegisterRequest } from "../types/authTypes";
import { MyUserProfile, BaseUser } from "../types/userTypes";
import { useRouter } from "next/navigation";

interface AuthContextType {
    user: BaseUser | null;
    loading: boolean;
    error: string | null;
    login: (data: LoginRequest) => Promise<void>;
    register: (data: RegisterRequest) => Promise<void>;
    logout: () => void;
    fetchProfile: () => Promise<MyUserProfile | null>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
    const [user, setUser] = useState<BaseUser | null>(null);
    const [loading, setLoading] = useState<boolean>(true);
    const [error, setError] = useState<string | null>(null);
    const router = useRouter();

    useEffect(() => {
        const loadUser = async () => {
            try {
                await authService.refreshToken();
                const profile = await userService.getMyProfile();
                setUser(profile);
            } catch {
                // Pas de session valide
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
            const profile = await userService.getMyProfile();
            setUser(profile);
            router.push("/");
        } catch (error) {
            setError("Login failed");
            throw error;
        } finally {
            setLoading(false);
        }
    };

    const register = async (data: RegisterRequest) => {
        try {
            setLoading(true);
            setError(null);
            await authService.register(data);
            const profile = await userService.getMyProfile();
            setUser(profile);
            router.push("/");
        } catch (error) {
            setError("Registration failed");
            throw error;
        } finally {
            setLoading(false);
        }
    };

    const logout = () => {
        authService.logout();
        setUser(null);
        router.push("/login");
    };

    const fetchProfile = useCallback(async (): Promise<MyUserProfile | null> => {
        try {
            const profile = await userService.getMyProfile();
            return profile;
        } catch (error) {
            setError("Failed to fetch profile");
            return null;
        }
    }, []);

    return (
        <AuthContext.Provider value={{ user, loading, error, login, register, logout, fetchProfile }}>
            {children}
        </AuthContext.Provider>
    );
}

export function useAuth() {
    const context = useContext(AuthContext);
    if (context === undefined) {
        throw new Error("useAuth must be used within an AuthProvider");
    }
    return context;
}

/*Cause du bug
Le problème est que useAuth est un hook simple avec un état local (useState), et non un Context React partagé. Chaque composant qui appelle useAuth() obtient sa propre instance indépendante du state user.

Voici ce qui se passe concrètement :

Sidebar appelle useAuth() → crée son propre user state (initialement null)
LoginForm appelle useAuth() → crée un autre user state (également null)
Quand LoginForm appelle login(), le setUser(profile) à la ligne 38 de useAuth ne met à jour que l'instance de LoginForm. Le user du Sidebar reste null.
Au refresh, le useEffect du Sidebar (ligne 14-29 de useAuth) s'exécute, fait refreshToken() + getMyProfile(), et retrouve l'utilisateur connecté.

export function useAuth() {
    const [user, setUser] = useState<BaseUser | null>(null);

Chaque appel à useAuth() crée un useState indépendant — c'est la racine du problème.

Solution
Il faut transformer useAuth en un AuthContext + AuthProvider pour que l'état d'authentification soit partagé entre tous les composants. Voici les étapes :

Créer un AuthContext avec createContext
Créer un AuthProvider qui encapsule la logique actuelle de useAuth et fournit le state via le Context
Wrapper l'application avec <AuthProvider>
Modifier useAuth pour qu'il consomme le Context via useContext
*/