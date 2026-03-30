import ProfileStats from "@/app/components/Profile/ProfileStats";
import UserProfileInfo from "@/app/components/Profile/UserProfileInfo";
import GetUserQuizzes from "@/app/components/Quizz/GetUserQuizzes";
import userService from "@/app/services/userService";
import { notFound } from "next/navigation";

export default async function PublicProfile({
  params,
}: {
  params: Promise<{ username: string }>;
}) {
  const { username } = await params;

  let profile = null;

  try {
    profile = await userService.getUserProfile(username);
  } catch (e) {
    notFound();
  }

  if (!profile) notFound();

  return (
    <div className="flex">
      <div>
        <UserProfileInfo />
        <ProfileStats username={username} />
      </div>
      {<GetUserQuizzes authorName={username} />}
    </div>
  );
}
