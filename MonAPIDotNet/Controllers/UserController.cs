using MonAPIDotNet.DTOs;
using MonAPIDotNet.Service;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using System.Text.RegularExpressions;
using System.IdentityModel.Tokens.Jwt;

namespace MonAPIDotNet.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly IUserService _userService;

        public UserController(IUserService userService)
        {
            _userService = userService;
        }

        // GET /api/user/users

        /// <summary>
        /// Récupère la liste de tous les utilisateurs avec leurs profils publics.
        /// </summary>
        /// <returns>Tous les utilisateurs avec leurs profils publics.</returns>
        /// <response code="200">Tous les utilisateurs avec leurs profils publics.</response>
        /// 
        [HttpGet("users")]
        [ProducesResponseType(typeof(List<UserProfileDTO>), StatusCodes.Status200OK)]
        public async Task<IActionResult> GetAllUsers()
        {
            var users = await _userService.GetAllUsersAsync();
            if (users == null)
            {
                return NotFound();
            }
            return Ok(users);
        }

        // GET /api/user/me

        /// <summary>
        /// Récupère le profil de l'utilisateur actuellement connecté.
        /// </summary>
        /// <param mae="userDto">Le profil de l'utilisateur actuellement connecté.</param>  
        /// <returns>Le profil de l'utilisateur actuellement connecté.</returns>
        /// <response code="200">Le profil de l'utilisateur actuellement connecté.</response>
        /// <response code="401">Non autorisé. L'utilisateur n'est pas authentifié.</response>
        /// <response code="404">Non trouvé. Le profil de l'utilisateur n'existe pas.</response>
        [HttpGet("me")]
        [Authorize]
        [ProducesResponseType(typeof(PrivateUserProfileDTO), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]

        public async Task<IActionResult> GetMyProfile()
        {
            var username = User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
            if (string.IsNullOrEmpty(username))
            {
                return Unauthorized("Invalid token.");
            }
            var userProfile = await _userService.GetMyProfileAsync(username);
            if (userProfile == null)
            {
                return NotFound();
            }
            return Ok(userProfile);
        }

        // GET /api/user/{username}

        /// <summary>
        /// Récupère le profil public d'un utilisateur par son nom d'utilisateur.
        /// </summary>
        /// <param name="username">Le nom d'utilisateur de l'utilisateur dont on veut récupérer le profil public.</param>
        /// <returns>Le profil public de l'utilisateur.</returns>
        /// <response code="200">Le profil public de l'utilisateur.</response>
        /// <response code="404">Non trouvé. L'utilisateur ou son profil public n'ex
        [HttpGet("{username}")]
        [ProducesResponseType(typeof(UserProfileDTO), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<IActionResult> GetUserProfile(string username)
        {
            var userProfile = await _userService.GetUserByUsernameAsync(username);
            if (userProfile == null)
            {
                return NotFound();
            }
            return Ok(userProfile);
        }

    }
}