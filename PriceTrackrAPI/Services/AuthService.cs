using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using PriceTrackrAPI.Model.DTO;
using PriceTrackrAPI.Services.Contract;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace PriceTrackrAPI.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityUser> _roleManager;
        private readonly IConfiguration _configuration;

        public AuthService(
            UserManager<IdentityUser> userManager, 
            RoleManager<IdentityUser> roleManager,
            IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }

        public async Task<(bool success, IEnumerable<string> Errors)> RegisterUserAsync(RegisterDTO model)
        {
            var user = new IdentityUser { UserName = model.Username };
            var result = await _userManager.CreateAsync(user, model.Password);

            if (result.Succeeded)
            {
                return (true, Array.Empty<string>());
            }

            return (false, result.Errors.Select(e => e.Description));
        }

        public async Task<(bool success, string token)> LoginUserAsync(LoginDTO model)
        {
            var user = await _userManager.FindByNameAsync(model.Username);
            if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
            {
                var userRoles = await _userManager.GetRolesAsync(user);

                var authClaims = new List<Claim>
                {
                    new Claim(JwtRegisteredClaimNames.Sub, user.UserName!),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };

                authClaims.AddRange(userRoles.Select(role => new Claim(ClaimTypes.Role, role)));

                var token = new JwtSecurityToken(
                    issuer: _configuration["Jwt:Issuer"],
                    expires: DateTime.Now.AddMinutes(double.Parse(_configuration["Jwt:ExpiryMinutes"]!)),
                    claims: authClaims,
                    signingCredentials: new Microsoft.IdentityModel.Tokens.SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JwtKey"]!)),
                    SecurityAlgorithms.HmacSha256
                    ));

                return (true, new JwtSecurityTokenHandler().WriteToken(token));

            }

            return (false, String.Empty);
        }

    }
}
