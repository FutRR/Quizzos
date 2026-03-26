"use client";

import { useState, useEffect } from "react";
import { useParams } from "next/navigation";
import { BaseUser } from "@/app/types/userTypes";
import userService from "@/app/services/userService";
import { useJsonPlaceholder } from "@/app/hooks/useJsonPlaceholder";
import { useQuiz } from "@/app/hooks/useQuiz";

export default function UserProfile() {
  const { images } = useJsonPlaceholder();
  const params = useParams<{ username: string }>();
  const username = params.username;
  const [profile, setProfile] = useState<BaseUser | null>(null);
  const { getQuizzesByAuthorName, quizzes } = useQuiz();

  useEffect(() => {
    const loadProfile = async () => {
      const profileData = await userService.getUserProfile(username);
      setProfile(profileData);
      if (profileData) {
        await getQuizzesByAuthorName(profileData.userName || "");
      }
    };
    loadProfile();
  }, [username]);

  const avatar = {
    image: images?.[0]
      ? `https://picsum.photos/400/300?random=${images[0].id}`
      : "",
    imageAlt: images?.[0]?.title || "Avatar de l'utilisateur",
  };
  console.log("Quizzes de l'auteur:", quizzes);
  return (
    <div>
      {profile ? (
        <div className="flex flex-col justify-end items-start text-center mb-4">
          <div className="flex">
            <img
              src={avatar.image}
              alt={avatar.imageAlt}
              className="w-32 h-32 rounded-full mb-4 object-cover"
            />
            <div className="ml-6 text-left">
              <h3 className="text-xl font-bold">{profile.userName}</h3>
              <p>Abonnés: 12</p>
            </div>
          </div>
          <div className="mb-6 text-left">
            <h2 className="text-lg font-semibold mb-1">Stats:</h2>
            <p>Quiz joués: {/*profile.stats.gamesPlayed*/}</p>
            <p>Quiz créés: {quizzes.length}</p>
            <p>Score Général: {/*profile.stats.totalScore*/}</p>
            <p>Tags favoris: {/*profile.stats.favoriteTags*/}</p>
          </div>
        </div>
      ) : (
        <p>
          Aucun utilisateur sous le nom de{" "}
          <span className="font-bold">{username}</span>
        </p>
      )}
    </div>
  );
}
