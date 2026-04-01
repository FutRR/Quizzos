using MonAPIDotNet.Data;
using MonAPIDotNet.DTOs;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using MonAPIDotNet.Exceptions;

namespace MonAPIDotNet.Service
{
    public interface IUserService
    {
        Task<List<UserProfileDTO>> GetAllUsersAsync();
        Task<UserProfileDTO> GetUserByIdAsync(string id);
        Task<UserProfileDTO> GetUserByUsernameAsync(string username);
        Task<UpdateUserProfileDTO> UpdateMyProfileAsync(string id, UpdateUserProfileDTO userDto);
        Task<PrivateUserProfileDTO> GetMyProfileAsync(string username);
    }
    public class UserService : IUserService
    {
        private readonly MyDbContext _context;
        private readonly UserManager<ApplicationUser> _userManager;
        public UserService(MyDbContext context, UserManager<ApplicationUser> userManager)
        {
            _context = context;
            _userManager = userManager;
        }
        public async Task<List<UserProfileDTO>> GetAllUsersAsync()
        {
            return await _context.Users
                .Include(u => u.UserProfile)
                .Where(u => u.UserProfile != null)
                .Select(u => new UserProfileDTO
                {
                    UserName = u.UserName!,
                    AvatarUrl = u.UserProfile!.AvatarUrl,
                    CreatedAt = u.UserProfile.CreatedAt
                })
                .ToListAsync();
        }

        public async Task<UserProfileDTO> GetUserByIdAsync(string id)
        {
            var user = await _context.Users
                .Include(u => u.UserProfile)
                .FirstOrDefaultAsync(u => u.Id == id);

            if (user == null || user.UserProfile == null)
                return null!;

            return new UserProfileDTO
            {
                UserName = user.UserName!,
                AvatarUrl = user.UserProfile.AvatarUrl,
                CreatedAt = user.UserProfile.CreatedAt
            };
        }

        public async Task<UserProfileDTO> GetUserByUsernameAsync(string username)
        {
            var user = await _context.Users
                .Include(u => u.UserProfile)
                .FirstOrDefaultAsync(u => u.UserName == username);

            if (user == null || user.UserProfile == null)
                return null!;

            return new UserProfileDTO
            {
                UserName = user.UserName!,
                AvatarUrl = user.UserProfile.AvatarUrl,
                CreatedAt = user.UserProfile.CreatedAt
            };
        }

        public async Task<PrivateUserProfileDTO> GetMyProfileAsync(string userId)
        {
            var user = await _context.Users
                .Include(u => u.UserProfile)
                .FirstOrDefaultAsync(u => u.Id == userId);

            if (user == null || user.UserProfile == null)
                return null!;
            return new PrivateUserProfileDTO
            {
                UserName = user.UserName!,
                AvatarUrl = user.UserProfile.AvatarUrl,
                CreatedAt = user.UserProfile.CreatedAt,
                Email = user.Email,
                IsEmailConfirmed = user.EmailConfirmed
            };
        }

        public async Task<UpdateUserProfileDTO> UpdateMyProfileAsync(string id, UpdateUserProfileDTO userDto)
        {
            var user = await _context.Users
                .Include(u => u.UserProfile)
                .FirstOrDefaultAsync(u => u.Id == id);

            if (user == null)
                throw new NotFoundException("User not found.", id);
            if (user.UserProfile == null)
                throw new NotFoundException("User profile not found.", id);

            // Mise à jour uniquement des champs fournis
            if (!string.IsNullOrEmpty(userDto.UserName))
                user.UserName = userDto.UserName;

            if (!string.IsNullOrEmpty(userDto.AvatarUrl) && Uri.TryCreate(userDto.AvatarUrl, UriKind.Absolute, out _))
                user.UserProfile.AvatarUrl = userDto.AvatarUrl;

            await _context.SaveChangesAsync();
            return new UpdateUserProfileDTO
            {
                UserName = user.UserName!,
                AvatarUrl = user.UserProfile.AvatarUrl,
            };
        }

    }
}