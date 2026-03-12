"use client";

import { useState, useEffect } from "react";
import { useAuth } from "@/app/hooks/useAuth";
import { MyUserProfile } from "@/app/types/userTypes";
import userService from "@/app/services/userService";
import authService from "@/app/services/authService";

export default function MyProfilePage() {
  const { user, logout } = useAuth();
  const [profile, setProfile] = useState<MyUserProfile | null>(null);

    useEffect(() => {
        const loadProfile = async () => {
            if (user) {
                const profileData = await userService.getMyProfile();
                setProfile(profileData);
            }
        };
        loadProfile();
    }, [user]);
  const options: Intl.DateTimeFormatOptions = {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
  };
    
  return (
    <div>
      <h1>Mon Profil</h1>
      {profile ? (
        <div>
          <p>Nom d'utilisateur: {profile.userName}</p>
          <p>Email: {profile.email}</p>
          <p>Email Vérifié: {profile.isEmailVerified ? "Oui" : "Non"}</p>
          <p>Créer le: {new Date(profile.createdAt).toLocaleDateString(undefined, options)}</p>
        </div>
      ) : (
        <p>Loading profile...</p>
      )}
      <button onClick={logout} className="mt-5 inline-block rounded-md bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-700">Déconnexion</button>
    </div>
  );
}