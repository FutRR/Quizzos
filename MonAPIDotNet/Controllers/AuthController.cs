using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using MonAPIDotNet.Models;
using MonAPIDotNet.Data;
using MonAPIDotNet.Service;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;

namespace MonAPIDotNet.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly JwtService _jwtService;

        public AuthController(JwtService jwtService, UserManager<ApplicationUser> userManager)
        {
            _jwtService = jwtService;
            _userManager = userManager;
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            var user = await _userManager.FindByNameAsync(request.Username);

            if (user == null || !await _userManager.CheckPasswordAsync(user, request.Password))
                return Unauthorized();
            if (!_jwtService.IsValidAudience(request.Audience))
                return BadRequest("Audience is invalid.");

            var userClaims = await _userManager.GetClaimsAsync(user);
            var token = _jwtService.GenerateJwtToken(user.UserName, request.Audience, userClaims.ToList());
            var refreshToken = _jwtService.GenerateRefreshToken();

            await _jwtService.SaveRefreshToken(request.Username, refreshToken);

            //Response
            Response.Cookies.Append("refreshToken", refreshToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = false, // TODO: Mettre à true en production (HTTPS)
                SameSite = SameSiteMode.Lax, // Lax pour permettre les requêtes cross-origin en dev
                Expires = DateTime.UtcNow.AddDays(7),
                Path = "/" // Accessible sur tout le domaine
            });

            return Ok(new { Token = token, RefreshToken = refreshToken });
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh([FromBody] RefreshRequest request)
        {
            var user = await _userManager.FindByNameAsync(request.Username);
            if (user == null || !await _jwtService.IsValidRefreshToken(request.RefreshToken))
                return Unauthorized();
            if (!_jwtService.IsValidAudience(request.Audience))
                return BadRequest("Audience is invalid.");

            var userClaims = await _userManager.GetClaimsAsync(user);
            var token = _jwtService.GenerateJwtToken(user.UserName, request.Audience, userClaims.ToList());
            var refreshToken = _jwtService.GenerateRefreshToken();

            // Revoke old refresh token
            await _jwtService.RevokeRefreshToken(request.RefreshToken);
            await _jwtService.SaveRefreshToken(request.Username, refreshToken);

            return Ok(new { Token = token, RefreshToken = refreshToken });
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            var user = new ApplicationUser
            {
                UserName = request.Username
            };
            var result = await _userManager.CreateAsync(user, request.Password);
            if (!result.Succeeded)
            {
                return BadRequest(result.Errors);
            }
            result = await _userManager.AddClaimsAsync(user, new[] { new Claim(JwtRegisteredClaimNames.Name, request.DisplayName) });
            if (!result.Succeeded)
            {
                return BadRequest(result.Errors);
            }
           
            return Ok();
        }
    }

}

