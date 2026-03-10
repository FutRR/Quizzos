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
    }
}