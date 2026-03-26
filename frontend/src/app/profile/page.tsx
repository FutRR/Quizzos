"use client";

import MyProfilePage from "../components/Profile/MyProfilePage";
import GetUserQuizzes from "../components/Quizz/GetUserQuizzes";
import { useAuth } from "../hooks/useAuth";

export default function Profile() {
  const { user, loading } = useAuth();
  
  return (
    <div>
      <MyProfilePage />
      {!loading && user && <GetUserQuizzes authorName={user.userName} />}
    </div>
  );
}