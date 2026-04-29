"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/app/hooks/useAuth";
import { MyUserProfile } from "@/app/types/userTypes";
import userService from "@/app/services/userService";
import { useJsonPlaceholder } from "@/app/hooks/useJsonPlaceholder";
import { Temporal } from "@js-temporal/polyfill";
import { useQuiz } from "@/app/hooks/useQuiz";
import { useProfile } from "@/app/hooks/useProfile";
import AvatarUpload from "../Images/AvatarUpload";

export default function MyProfilePage() {
  const { user, loading } = useAuth();
  const router = useRouter();
  const { images } = useJsonPlaceholder();
  const { updateMyProfile, error } = useProfile();
  const [profile, setProfile] = useState<MyUserProfile | null>(null);
  const { getQuizzesByAuthorName, quizzes } = useQuiz();

  // Etats pour les champs du formulaire
  const [displayName, setDisplayName] = useState("");
  const [avatarUrl, setAvatarUrl] = useState("");

  const [edit, setEdit] = useState(false);
  const toggle = () => setEdit((prev) => !prev);

  useEffect(() => {
    if (loading) return;
    if (!user) {
      router.push("/login");
      return;
    }

    const loadProfile = async () => {
      try {
        const profileData = await userService.getMyProfile();
        setProfile(profileData);
        setDisplayName(profileData.displayName);
        setAvatarUrl(profileData.avatarUrl || "");
      } catch (err) {
        // fetchClient redirects to /login on 401; avoid unhandled promise rejection here.
        console.error("[MyProfilePage] Error while loading profile:", err);
      }
    };
    loadProfile();
  }, [user, loading, router]);

  const handleSubmit = async (e: React.SubmitEvent<HTMLFormElement>) => {
    e.preventDefault();
    try {
      const updatedProfile = await updateMyProfile({
        displayName,
        avatarUrl,
      });
      if (updatedProfile) {
        router.push(`/profile`);
        toggle();
        location.reload(); // Forcer le rechargement de la page pour voir les changements
      }
    } catch {
      // error is already set in useProfile state
    }
  };

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
          {!edit ? (
            <div className="flex">
              <img
                src={profile.avatarUrl || avatar.image}
                alt={`Photo de profil de ${profile.userName}`}
                className="w-32 h-32 rounded-full object-cover"
              />
              <div className="ml-6 text-left">
                <h3 className="text-xl font-bold">{profile.displayName}</h3>
                <p className="text-gray-600">@{profile.userName}</p>
                <p>Abonnés: 12</p>
                <button
                  className="bg-blue-800 hover:bg-blue-700 border border-blue-900 text-white font-bold py-1 px-2 rounded"
                  onClick={toggle}
                >
                  Modifier
                </button>
              </div>
            </div>
          ) : (
            <form className="space-y-4 p-0 m-0" onSubmit={handleSubmit}>
              <div className="flex">
                <AvatarUpload onImageUploaded={setAvatarUrl} />
                <div className="ml-6 text-left">
                  <input
                    className="text-xl font-bold border border-gray-300 rounded"
                    id="displayName"
                    type="text"
                    placeholder={profile?.displayName}
                    value={displayName}
                    onChange={(e) => setDisplayName(e.target.value)}
                  />
                  <p className="text-gray-600">@{profile.userName}</p>
                  <p>Abonnés: 12</p>
                  <div className="flex gap-2">
                    <button
                      className="bg-green-800 hover:bg-green-700 border border-green-900 text-white font-bold py-1 px-2 rounded"
                      type="submit"
                    >
                      Sauvegarder
                    </button>
                    <button
                      className="bg-red-800 hover:bg-red-700 border border-red-900 text-white py-1 px-2 rounded"
                      type="button"
                      onClick={toggle}
                    >
                      Annuler
                    </button>
                  </div>
                </div>
              </div>
            </form>
          )}
          <div className="flex flex-col">
            {user?.userName === profile.userName && (
              <div className="mt-4 mb-6 text-left">
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
