"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import ImageUpload from "../Images/ImageUpload";
import { MyUserProfile } from "@/app/types/userTypes";
import { useProfile } from "@/app/hooks/useProfile";
import userService from "@/app/services/userService";

export default function ProfileEdit() {
  const router = useRouter();
  const { updateMyProfile, error, loading } = useProfile();
  const [profile, setProfile] = useState<MyUserProfile | null>(null);
  // Etats pour les champs du formulaire
  const [userName, setUserName] = useState("");
  const [avatarUrl, setAvatarUrl] = useState("");

  useEffect(() => {
    const loadProfile = async () => {
      const profileData = await userService.getMyProfile();
      setProfile(profileData);
      setUserName(profileData.userName);
      setAvatarUrl(profileData.avatarUrl || ""); // Assurez-vous que avatarUrl est une chaîne, même si elle est vide
    };
    loadProfile();
  }, []);

  const handleSubmit = async (e: React.SubmitEvent<HTMLFormElement>) => {
    e.preventDefault();
    try {
      const updatedProfile = await updateMyProfile({
        userName,
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
        <h1>Edit Profile</h1>
        <form className="mb-6 space-y-4" onSubmit={handleSubmit}>
          <label htmlFor="username">Nom d'utilisateur : </label>
          <input
            id="username"
            type="text"
            placeholder={profile?.userName}
            value={userName}
            onChange={(e) => setUserName(e.target.value)}
          />
          <ImageUpload
            onImageUploaded={setAvatarUrl}
            currentImageUrl={avatarUrl}
          />
          <button
            className="bg-green-500 hover:bg-green-700 text-white font-bold py-2 px-4 w-1/2 self-center rounded"
            type="submit"
          >
            Sauvegarder
          </button>
        </form>
      </div>
    </>
  );
}
