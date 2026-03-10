using Microsoft.AspNetCore.Identity;

namespace MonAPIDotNet.Data
{
    public class ApplicationUser : IdentityUser
    {
        public UserProfile? UserProfile { get; set; }
    }
}
