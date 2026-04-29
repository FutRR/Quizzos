"use client";

import { useState, useEffect } from "react";
import { BaseUser } from "@/app/types/userTypes";
import userService from "@/app/services/userService";
import { useJsonPlaceholder } from "@/app/hooks/useJsonPlaceholder";
import { useParams } from "next/navigation";

export default function UserProfileInfo() {
  const params = useParams<{ username: string }>();
  const username = params.username;
  const { images } = useJsonPlaceholder();
  const [profile, setProfile] = useState<BaseUser | null>(null);

  useEffect(() => {
    const loadProfile = async () => {
      const profileData = await userService.getUserProfile(username);
      setProfile(profileData);
    };
    loadProfile();
  }, [username]);

  const avatar = {
    image: images?.[0]
      ? `https://picsum.photos/400/300?random=${images[0].id}`
      : "",
    imageAlt: images?.[0]?.title || "Avatar de l'utilisateur",
  };

  return (
    <div>
      {profile ? (
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
      ) : (
        <p>Loading profile...</p>
      )}
    </div>
  );
}
