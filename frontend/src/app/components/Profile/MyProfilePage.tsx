"use client";

import { useState, useEffect } from "react";
import { useAuth } from "@/app/hooks/useAuth";
import { MyUserProfile } from "@/app/types/userTypes";
import userService from "@/app/services/userService";
import authService from "@/app/services/authService";

export default function MyProfilePage() {
  const { user, logout } = useAuth();
  const [profile, setProfile] = useState<MyUserProfile | null>(null);

    useEffect(() => {
        const loadProfile = async () => {
            if (user) {
                const profileData = await userService.getMyProfile();
                setProfile(profileData);
            }
        };
        loadProfile();
    }, [user]);
    
  return (
    <div>
      <h1>My Profile</h1>
      {profile ? (
        <div>
          <p>Username: {profile.userName}</p>
          <p>Email: {profile.email}</p>
          <p>Email Verified: {profile.isEmailVerified ? "Yes" : "No"}</p>
          <p>Created At: {profile.createdAt}</p>
        </div>
      ) : (
        <p>Loading profile...</p>
      )}
      <button onClick={logout} className="mt-5 inline-block rounded-md bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-700">Logout</button>
    </div>
  );
}