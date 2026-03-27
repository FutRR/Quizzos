"use client";

import userService from "@/app/services/userService";
import { useQuiz } from "@/app/hooks/useQuiz";
import { useEffect, useState } from "react";
import { BaseUser } from "@/app/types/userTypes";
import { useAuth } from "@/app/hooks/useAuth";
import { useParams } from "next/navigation";

export default function ProfileStats() {
  const params = useParams<{ username: string }>();
  const username = params.username;
  const { user } = useAuth();
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
  }, []);

  return (
    <div>
      {profile ? (
        <div className="mb-6 text-left">
          <h2 className="text-lg font-semibold mb-1">Stats:</h2>
          <p>Quiz joués: {/*profile?.stats.gamesPlayed*/}</p>
          <p>Quiz créés: {quizzes.length}</p>
          <p>Score Général: {/*profile.stats.totalScore*/}</p>
          <p>Tags favoris: {/*profile.stats.favoriteTags*/}</p>
        </div>
      ) : (
        <p>Loading stats...</p>
      )}
    </div>
  );
}
