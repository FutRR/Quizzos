using MonAPIDotNet.DTOs;
using MonAPIDotNet.Service;
using MonAPIDotNet.Exceptions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
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
        /// <param name="userDto">Le profil de l'utilisateur actuellement connecté.</param>
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
            var userId = User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
            if (string.IsNullOrEmpty(userId))
            {
                return Unauthorized("Invalid token.");
            }
            var userProfile = await _userService.GetMyProfileAsync(userId);
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
        /// <response code="404">Non trouvé. L'utilisateur ou son profil public n'existe pas.</response>
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

        // PATCH /api/user/me

        /// <summary>
        /// Met à jour le profil de l'utilisateur actuellement connecté.
        /// </summary>
        /// <param name="userDto">Les données du profil à mettre à jour.</param>
        /// <returns>Le profil mis à jour de l'utilisateur actuellement connecté.</returns>
        /// <response code="200">Le profil mis à jour de l'utilisateur actuellement connecté.</response>
        /// <response code="400">Requête invalide. Les données fournies sont invalides.</response>
        /// <response code="401">Non autorisé. L'utilisateur n'est pas authentifié.</response>
        /// <response code="404">Non trouvé. Le profil de l'utilisateur n'existe pas.</response>
        [HttpPatch("me")]
        [Authorize]
        [ProducesResponseType(typeof(UserProfileDTO), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<ActionResult<UserProfileDTO>> UpdateMyProfile([FromBody] UpdateUserProfileDTO userDto)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            if (userDto == null || (string.IsNullOrEmpty(userDto.UserName) && string.IsNullOrEmpty(userDto.AvatarUrl)))
                return BadRequest("Au moins un champ doit être fourni.");

            var userId = User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
            if (string.IsNullOrEmpty(userId))
                return Unauthorized();

            try
            {
                var updatedUserProfile = await _userService.UpdateMyProfileAsync(userId, userDto);
                return Ok(updatedUserProfile);
            }
            catch (NotFoundException ex)
            {
                return NotFound(ex.Message);

            }

        }
    }
}