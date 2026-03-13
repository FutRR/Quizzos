"use client";

import { useState, useEffect } from "react";
import { useAuth } from "@/app/hooks/useAuth";
import { MyUserProfile } from "@/app/types/userTypes";
import userService from "@/app/services/userService";


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
    <div className="flex flex-col min-h-screen items-center justify-center bg-zinc-50 font-sans dark:bg-black">
      <h1 className="text-2xl font-bold mb-4">Mon Profil</h1>
      {profile ? (
        <div className="flex-1 bg-gray-800 rounded-2xl shadow-xl p-8 border border-gray-700 h-full w-full max-w-md">
          <div className="flex flex-col items-start text-center mb-4">
            <h2 className="text-lg font-semibold mb-2">Informations</h2>
            <p>Nom d'utilisateur: {profile.userName}</p>
            <p>Email: {profile.email ? profile.email : "Non spécifié"}</p>
            <p>Email Vérifié: {profile.isEmailVerified ? "Oui" : "Non"}</p>
            <p>Créer le: {new Date(profile.createdAt).toLocaleDateString(undefined, options)}</p>
          </div>
          <div className="flex flex-col items-start text-center mb-4">
            <h2 className="text-lg font-semibold mb-2">Stats:</h2>
            <p>Quizz joués: {/*profile.stats.gamesPlayed*/}</p>
            <p>Quizz créés: {/*profile.stats.gamesCreated*/}</p>
            <p>Score Général: {/*profile.stats.totalScore*/}</p>
            <p>Tags favoris: {/*profile.stats.favoriteTags*/}</p>
            <p>Abonnés: {/*profile.stats.subscribers*/}</p>
          </div>
        </div>
      ) : (
        <p>Loading profile...</p>
      )}
      <button onClick={logout} className="mt-5 inline-block rounded-md bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-700">Déconnexion</button>
    </div>
  );
}