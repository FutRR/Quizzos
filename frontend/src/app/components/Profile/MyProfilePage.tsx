"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/app/hooks/useAuth";
import { MyUserProfile } from "@/app/types/userTypes";
import userService from "@/app/services/userService";
import { useJsonPlaceholder } from "@/app/hooks/useJsonPlaceholder";
import { Temporal } from "@js-temporal/polyfill";


export default function MyProfilePage() {
  const { user, logout, loading } = useAuth();
  const router = useRouter();
  const { images } = useJsonPlaceholder();
  const [profile, setProfile] = useState<MyUserProfile | null>(null);

  useEffect(() => {
    if (loading) return;
    if (!user) {
      router.push("/login");
      return;
    }

    const loadProfile = async () => {
      const profileData = await userService.getMyProfile();
      setProfile(profileData);
    };
    loadProfile();
  }, [user, loading, router]);

  const options: Intl.DateTimeFormatOptions = {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
  };

  const avatar = {
    image: images?.[0]? `https://picsum.photos/400/300?random=${images[0].id}&grayscale` : "",
    imageAlt: images?.[0]?.title || "Avatar de l'utilisateur",
  }
    console.log(profile?.createdAt)
  return (
    <div>
      <h1 className="text-2xl font-bold mb-4">Mon Profil</h1>
      {profile ? (
          <div className="flex flex-col justify-start items-start text-center mb-4">
            <div className="flex">
              <img src={avatar.image} alt={avatar.imageAlt} className="w-32 h-32 rounded-full mb-4 object-cover" />
              <div className="ml-6 text-left">
                <h3 className="text-xl font-bold">{profile.userName}</h3>
                <p>Email: {profile.email ? profile.email : "Non spécifié"}</p>
                <p>Email Vérifié: {profile.isEmailVerified ? "Oui" : "Non"}</p>
                <p>Compte crée le: {Temporal.PlainDateTime.from(profile.createdAt).toLocaleString(undefined, options)}</p>
              </div>
            </div>
          <div className="text-left">
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