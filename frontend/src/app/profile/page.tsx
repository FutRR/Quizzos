"use client";

import ProfileEdit from "../components/Profile/ProfileEdit";
import ProfileInfo from "../components/Profile/MyProfileInfo";
import ProfileStats from "../components/Profile/ProfileStats";
import GetUserQuizzes from "../components/Quizz/GetUserQuizzes";
import { useAuth } from "../hooks/useAuth";
import { useState } from "react";
import { AvatarViewer } from "../components/Three/Avatar";

export default function Profile() {
  const { user, loading } = useAuth();
  const [edit, setEdit] = useState(false);
  const toggle = () => setEdit((prev) => !prev);

  return (
    <div className="flex justify-between px-16 gap-8">
      <div className="flex flex-col w-1/2">
        {!edit ? (
          <div>
            <ProfileInfo />
          </div>
        ) : (
          <div>
            <ProfileEdit />
          </div>
        )}
        <button
          className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 w-1/4 rounded"
          onClick={toggle}
        >
          Modifier
        </button>
        <div>
          {!loading && user && <ProfileStats username={user.userName} />}
        </div>
      </div>
      <div className="w-1/2">
        <h2 className="text-lg font-semibold mb-1">My Quizzes :</h2>
        {!loading && user && (
          <GetUserQuizzes authorName={user.userName} limit={3} />
        )}
      </div>
      <div className="w-1/2">
        <AvatarViewer className="w-full h-full" style={{ width: '100%', height: '100%' }} />
      </div>
    </div>
  );
}
