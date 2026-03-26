import UserProfile from "@/app/components/Profile/UserProfile";
import GetUserQuizzes from "@/app/components/Quizz/GetUserQuizzes";

export default async function PublicProfile({ params }: { params: Promise<{ username: string }> }) {
  const { username } = await params;
  return (
    <div>
      <UserProfile />
      <GetUserQuizzes authorName={username} />
    </div>
  );
}
