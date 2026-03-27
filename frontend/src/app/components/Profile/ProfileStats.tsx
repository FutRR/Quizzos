"use client";

import userService from "@/app/services/userService";
import { useQuiz } from "@/app/hooks/useQuiz";
import { useEffect, useState } from "react";
import { BaseUser } from "@/app/types/userTypes";
import { useAuth } from "@/app/hooks/useAuth";

interface ProfileStatsProps {
  username: string;
}

export default function ProfileStats({ username }: ProfileStatsProps) {
  const { user } = useAuth();
  const [profile, setProfile] = useState<BaseUser | null>(null);
  const [userQuizzes, setUserQuizzes] = useState<any[]>([]);
  const { getQuizzesByAuthorName } = useQuiz();

  useEffect(() => {
    const loadProfile = async () => {
      const targetUsername = username || user?.userName;
      if (!targetUsername) return;
      
      const profileData = await userService.getUserProfile(targetUsername);
      setProfile(profileData);
      if (profileData) {
        const quizzes = await getQuizzesByAuthorName(profileData.userName || "");
        setUserQuizzes(quizzes || []);
      }
    };
    loadProfile();
  }, [username, user]);

  return (
    <div>
      {profile ? (
        <div className="mb-6 text-left">
          <h2 className="text-lg font-semibold mb-1">Stats:</h2>
          <p>Quiz joués: {/*profile?.stats.gamesPlayed*/}</p>
          <p>Quiz créés: {userQuizzes.length}</p>
          <p>Score Général: {/*profile.stats.totalScore*/}</p>
          <p>Tags favoris: {/*profile.stats.favoriteTags*/}</p>
        </div>
      ) : (
        <p>Loading stats...</p>
      )}
    </div>
  );
}