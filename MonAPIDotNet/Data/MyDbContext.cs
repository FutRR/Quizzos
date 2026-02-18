using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace MonAPIDotNet.Data
{
    public class MyDbContext : IdentityDbContext<ApplicationUser>
    {
        public DbSet<AuthorizedApplication> AuthorizedApplications { get; set; }
        public DbSet<RefreshToken> RefreshTokens { get; set; }
        public MyDbContext(DbContextOptions<MyDbContext> options) : base(options)
        {
        }
    }
}
