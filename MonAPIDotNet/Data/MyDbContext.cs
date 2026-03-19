using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace MonAPIDotNet.Data
{
    public class MyDbContext : IdentityDbContext<ApplicationUser>
    {
        /********** Identity and Authentication **********/
        public DbSet<AuthorizedApplication> AuthorizedApplications { get; set; }
        public DbSet<RefreshToken> RefreshTokens { get; set; }
        public DbSet<UserProfile> UserProfiles { get; set; }
        /********** Quiz and Related Entities **********/
        public DbSet<Quiz> Quizzes { get; set; }
        public DbSet<Tag> Tags { get; set; }
        public DbSet<QuizTag> QuizTags { get; set; }
        public DbSet<Question> Questions { get; set; }
        public DbSet<QuestionImage> QuestionImages { get; set; }
        public DbSet<Answer> Answers { get; set; }
        public MyDbContext(DbContextOptions<MyDbContext> options) : base(options)
        {
        }
    }
}
