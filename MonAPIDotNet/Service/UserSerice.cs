using MonAPIDotNet.Data;
using MonAPIDotNet.DTOs;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;

namespace MonAPIDotNet.Service
{
    public interface IUserService
    {
        Task<List<UserProfileDTO>> GetAllUsersAsync();
        Task<UserProfileDTO> GetUserByIdAsync(string id);
        Task<UserProfileDTO> GetUserByUsernameAsync(string username);
        Task<bool> UpdateUserAsync(string id, UserProfileDTO userDto);
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

            public async Task<bool> UpdateUserAsync(string id, UserProfileDTO userDto)
            {
                var user = await _context.Users
                    .Include(u => u.UserProfile)
                    .FirstOrDefaultAsync(u => u.Id == id);

                if (user?.UserProfile == null)
                    return false;
                
                // Mise à jour uniquement des champs fournis
                if (userDto.AvatarUrl != null)
                    user.UserProfile.AvatarUrl = userDto.AvatarUrl;

                _context.UserProfiles.Update(user.UserProfile);

                await _context.SaveChangesAsync();
                return true;
            }

    }
}