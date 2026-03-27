import ProfileStats from "@/app/components/Profile/ProfileStats";
import UserProfileInfo from "@/app/components/Profile/UserProfileInfo";
import GetUserQuizzes from "@/app/components/Quizz/GetUserQuizzes";

export default async function PublicProfile({
  params,
}: {
  params: Promise<{ username: string }>;
}) {
  const { username } = await params;

  return (
    <div className="flex">
      <div>
        <UserProfileInfo />
        <ProfileStats />
      </div>
      {<GetUserQuizzes authorName={username} />}
    </div>
  );
}
