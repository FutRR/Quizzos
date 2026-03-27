"use client";

import ProfileEdit from "../components/Profile/ProfileEdit";
import ProfileInfo from "../components/Profile/MyProfileInfo";
import ProfileStats from "../components/Profile/ProfileStats";
import GetUserQuizzes from "../components/Quizz/GetUserQuizzes";
import { useAuth } from "../hooks/useAuth";

export default function Profile() {
  const { user, loading } = useAuth();

  let edit = false;
  const toggle = () => {
    edit = true;
  };

  return (
    <div className="flex">
      <div>
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
          className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded"
          onClick={toggle}
        >
          Edit
        </button>
        {!loading && user && <ProfileStats username={user.userName} />}
      </div>
      {!loading && user && <GetUserQuizzes authorName={user.userName} />}
    </div>
  );
}
