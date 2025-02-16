﻿using FluentEmail.Core;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Tokens;
using PriceTrackrAPI.Model.DTO;
using PriceTrackrAPI.Services.Contract;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Policy;
using System.Text;

namespace PriceTrackrAPI.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly IFluentEmail _fluentEmail;

        public AuthService(
            UserManager<IdentityUser> userManager, 
            RoleManager<IdentityRole> roleManager,
            IConfiguration configuration,
            IFluentEmail fluentEmail)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _fluentEmail = fluentEmail;
        }

        public async Task<(bool success, IEnumerable<string> Errors)> RegisterUserAsync(RegisterDTO model, string baseUrl)
        {
            var user = new IdentityUser { UserName = model.Username, Email = model.Email };
            var result = await _userManager.CreateAsync(user, model.Password);

            if (result.Succeeded)
            {
                // Token generation
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                // Confirmation link (using absolute URL)
                var encodedEmail = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(user.Email));
                var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));

                var confirmationLink = string.Format(
                    "{0}?encodedEmail={1}&encodedToken={2}",
                    baseUrl,
                    Uri.EscapeDataString(encodedEmail),
                    Uri.EscapeDataString(encodedToken)
                    );

                // Email verification
                await _fluentEmail
                    .To(model.Email)
                    .Subject("Email verification for PriceTrackr")
                    .Body($"<p>To verify your email address click <a href='{confirmationLink}'>here </a></p>", isHtml:true)
                    .SendAsync();

                return (true, Array.Empty<string>());
            }

            return (false, result.Errors.Select(e => e.Description));
        }

        public async Task<(bool success, IEnumerable<string> Errors)> ConfirmEmailAsync(string email, string token)
        {
            var user = await _userManager.FindByEmailAsync(email);

            if (user == null)
            {
                return (false, new[] { "User email cannot be found" });
            }

            var result = await _userManager.ConfirmEmailAsync(user, token);
            if (result.Succeeded)
            {
                return (true, Array.Empty<string>());
            }

            return (false, new[] { "Email confirmation failed" });

        }

        public async Task<(bool success, string token)> LoginUserAsync(LoginDTO model)
        {
            var user = await _userManager.FindByNameAsync(model.Username);
            if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
            {
                var token = await GenerateJwtToken(user);
                return (true, token);

            }

            return (false, String.Empty);
        }

        public async Task<(bool success, IEnumerable<string> Errors)> AddRoleAsync(string role)
        {
            if (!await _roleManager.RoleExistsAsync(role))
            {
                var result = await _roleManager.CreateAsync(new IdentityRole(role));
                if (result.Succeeded)
                {
                    return (true, Array.Empty<string>());
                }

                return (false, result.Errors.Select(e => e.Description));
            }

            return (false, new[] { "Role already exists" });
        }

        public async Task<(bool success, IEnumerable<string> Errors)> AssignRoleAsync(UserRoleDTO model)
        {
            var user = await _userManager.FindByNameAsync(model.Username);

            if (user == null)
            {
                return (false, new[] { "User not found" });
            }

            var result = await _userManager.AddToRoleAsync(user, model.Role);

            if (result.Succeeded)
                return (true, Array.Empty<string>());

            return (false, result.Errors.Select(e => e.Description));
        }

        public async Task<string> GenerateJwtToken(IdentityUser user)
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
                signingCredentials: new Microsoft.IdentityModel.Tokens.SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!)),
                SecurityAlgorithms.HmacSha256
                ));

            var tokenHandler = new JwtSecurityTokenHandler().WriteToken(token);

            return tokenHandler;
        }

    }
}
