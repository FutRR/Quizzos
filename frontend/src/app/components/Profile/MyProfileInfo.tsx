"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/app/hooks/useAuth";
import { MyUserProfile } from "@/app/types/userTypes";
import userService from "@/app/services/userService";
import { useJsonPlaceholder } from "@/app/hooks/useJsonPlaceholder";
import { Temporal } from "@js-temporal/polyfill";
import { useQuiz } from "@/app/hooks/useQuiz";


export default function MyProfilePage() {
  const { user, loading } = useAuth();
  const router = useRouter();
  const { images } = useJsonPlaceholder();
  const [profile, setProfile] = useState<MyUserProfile | null>(null);
  const { getQuizzesByAuthorName, quizzes } = useQuiz();

  useEffect(() => {
    if (loading) return;
    if (!user) {
      router.push("/login");
      return;
    }

    const loadProfile = async () => {
      const profileData = await userService.getMyProfile();
      setProfile(profileData);
      if (profileData) {
        await getQuizzesByAuthorName(profileData.userName || "");
      }
    };
    loadProfile();
  }, [user, loading, router]);

  const options: Intl.DateTimeFormatOptions = {
    year: "numeric",
    month: "long",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  };

  const avatar = {
    image: images?.[0]
      ? `https://picsum.photos/400/300?random=${images[0].id}`
      : "",
    imageAlt: images?.[0]?.title || "Avatar de l'utilisateur",
  };

  return (
    <div>
      {profile ? (
        <div className="flex flex-col justify-end items-start text-center">
          <div className="flex">
            <img
              src={profile.avatarUrl || avatar.image}
              alt={`Photo de profil de ${profile.userName}`}
              className="w-32 h-32 rounded-full mb-4 object-cover"
            />
            <div className="ml-6 text-left">
              <h3 className="text-xl font-bold">{profile.displayName}</h3>
              <p className="text-gray-600">@{profile.userName}</p>
              <p>Abonnés: 12</p>
            </div>
          </div>
          <div className="flex flex-col">
            {user?.userName === profile.userName && (
              <div className="mb-6 text-left">
                <h2 className="text-lg font-semibold mb-1">Informations:</h2>
                <p>Email: {profile.email ? profile.email : "Non spécifié"}</p>
                <p>Email Vérifié: {profile.isEmailVerified ? "Oui" : "Non"}</p>
                <p>
                  Compte crée le:{" "}
                  {Temporal.PlainDateTime.from(
                    profile.createdAt,
                  ).toLocaleString(undefined, options)}
                </p>
              </div>
            )}
          </div>
        </div>
      ) : (
        <p>Loading profile...</p>
      )}
    </div>
  );
}
