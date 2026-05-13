using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using MonAPIDotNet.Models;

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
        public DbSet<QuizAttempt> QuizAttempts { get; set; }
        public DbSet<ImpostorGameSession> ImpostorGameSessions { get; set; }
        public DbSet<ImpostorPlayer> ImpostorPlayers { get; set; }
        public DbSet<ImpostorWordPair> ImpostorWordPairs { get; set; }
        public DbSet<GeoGameSession> GeoGameSessions { get; set; }
        public DbSet<GeoGameRound> GeoGameRounds { get; set; }
        
        public MyDbContext(DbContextOptions<MyDbContext> options) : base(options)

        {
        }
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // Configure many-to-many relationship between Quiz and Tag
            modelBuilder.Entity<QuizTag>()
                .HasKey(qt => new { qt.QuizId, qt.TagId });

            modelBuilder.Entity<QuizTag>()
                .HasOne(qt => qt.Quiz)
                .WithMany(q => q.QuizTags)
                .HasForeignKey(qt => qt.QuizId)
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<QuizTag>()
                .HasOne(qt => qt.Tag)
                .WithMany(t => t.QuizTags)
                .HasForeignKey(qt => qt.TagId)
                .OnDelete(DeleteBehavior.Cascade);

            // Indexes for performance
            modelBuilder.Entity<Quiz>()
                .HasIndex(q => q.Title);

            modelBuilder.Entity<Quiz>()
                .HasIndex(q => q.AuthorId);

            modelBuilder.Entity<Quiz>()
                .HasIndex(q => q.CreatedAt);

            // QuizAttempt config
            modelBuilder.Entity<QuizAttempt>()
                .HasIndex(a => new { a.UserId, a.QuizId });

            modelBuilder.Entity<QuizAttempt>()
                .HasOne(a => a.User)
                .WithMany()
                .HasForeignKey(a => a.UserId)
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<QuizAttempt>()
                .HasOne(a => a.Quiz)
                .WithMany()
                .HasForeignKey(a => a.QuizId)
                .OnDelete(DeleteBehavior.NoAction); // NoAction pour éviter le cycle de cascade via User→Quiz + User→QuizAttempt

            // Seed data
            modelBuilder.Entity<AuthorizedApplication>().HasData(
                new AuthorizedApplication { Id = 1, Audience = "API_App" }
            );

        }
    }
}
