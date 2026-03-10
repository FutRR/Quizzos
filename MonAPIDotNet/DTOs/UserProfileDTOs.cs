using System.ComponentModel.DataAnnotations;

namespace MonAPIDotNet.DTOs
{
    public class UserProfileDTO
    {
        public string UserName { get; set; } = null!;
        public string? AvatarUrl { get; set; }
        public DateTime CreatedAt { get; set; }
    }

    public class PrivateUserProfileDTO : UserProfileDTO
    {
        [EmailAddress]
        public string? Email { get; set; }
        public bool IsEmailConfirmed { get; set; }
    }

    public class UpdateUserProfileDTO
    {
        public string? UserName { get; set; }
        [Url]
        public string? AvatarUrl { get; set; }
    }

}