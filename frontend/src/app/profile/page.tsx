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
  const [animation, setAnimation] = useState<'Waving' | 'Defeated' | 'Celebrate'>('Defeated');
  const [color, setColor] = useState('#000000');

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
      <div className="flex flex-col items-center">
        <div className="w-126 h-126">
          <AvatarViewer animation={animation} color={color} className="w-full h-full" style={{ width: '100%', height: '100%' }} />
        </div>
        <div className="flex gap-2">
          <button onClick={() => setAnimation('Waving')}>Waving</button>
          <button onClick={() => setAnimation('Defeated')}>Defeated</button>
          <button onClick={() => setAnimation('Celebrate')}>Celebrate</button>
          <input type="color" value={color} onChange={(e) => setColor(e.target.value)} />
        </div>
      </div>
    </div>
  );
}
