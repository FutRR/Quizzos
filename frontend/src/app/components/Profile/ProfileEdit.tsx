"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import AvatarUpload from "../Images/AvatarUpload";
import { MyUserProfile } from "@/app/types/userTypes";
import { useProfile } from "@/app/hooks/useProfile";
import userService from "@/app/services/userService";

export default function ProfileEdit() {
  const router = useRouter();
  const { updateMyProfile, error, loading } = useProfile();
  const [profile, setProfile] = useState<MyUserProfile | null>(null);
  // Etats pour les champs du formulaire
  const [displayName, setDisplayName] = useState("");
  const [avatarUrl, setAvatarUrl] = useState("");

  useEffect(() => {
    const loadProfile = async () => {
      const profileData = await userService.getMyProfile();
      setProfile(profileData);
      setDisplayName(profileData.displayName);
      setAvatarUrl(profileData.avatarUrl || ""); // Assurez-vous que avatarUrl est une chaîne, même si elle est vide
    };
    loadProfile();
  }, []);

  const handleSubmit = async (e: React.SubmitEvent<HTMLFormElement>) => {
    e.preventDefault();
    try {
      const updatedProfile = await updateMyProfile({
        displayName,
        avatarUrl,
      });
      if (updatedProfile) {
        router.push(`/profile`);
      }
    } catch {
      // error is already set in useProfile state
    }
  };

  return (
    <>
      {error && <p>{error}</p>}
      {loading && <p>Loading...</p>}
      <div>
        <form className="mb-6 space-y-4" onSubmit={handleSubmit}>
          <div className="flex">
            <AvatarUpload
              onImageUploaded={setAvatarUrl}
              currentImageUrl={profile?.avatarUrl || ""}
            />
            <div className="flex flex-col justify-start items-start ml-6 text-left">
              <input
                className="text-xl font-bold px-1 border border-gray-300 rounded mb-4 w-1/2"
                id="displayName"
                type="text"
                placeholder={profile?.displayName}
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
              />
              <button
                className="bg-green-500 hover:bg-green-700 text-white font-bold py-2 px-4 w-1/2 rounded"
                type="submit"
              >
                Sauvegarder
              </button>
            </div>
          </div>
        </form>
      </div>
    </>
  );
}
