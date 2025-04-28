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
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly IConfiguration _configuration;
        private readonly IEmailService _emailService;

        public AuthService(
            UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager,
            SignInManager<IdentityUser> signInManager,
            IConfiguration configuration,
            IEmailService emailService)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _signInManager = signInManager;
            _configuration = configuration;
            _emailService = emailService;
        }

        /**
         Register User
        */
        public async Task<(bool success, IEnumerable<string> Errors)> RegisterUserAsync(RegisterDTO model)
        {
            var user = new IdentityUser { UserName = model.Username, Email = model.Email };
            var result = await _userManager.CreateAsync(user, model.Password);

            if (result.Succeeded)
            {
                // Token generation
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                var otp = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");
                // Confirmation link (using absolute URL)
                var encodedEmail = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(user.Email));
                var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));


                var confirmationLink = string.Format(
                    "{0}?encodedEmail={1}&encodedToken={2}&campaign=welcome",
                    _configuration["baseUrl"] + "/auth/confirm-email",
                    Uri.EscapeDataString(encodedEmail),
                    Uri.EscapeDataString(encodedToken)
                    );

                var emailBody = $"<p>To verify your email address click <a href='{confirmationLink}'>here </a></p>";
                var emailHeader = $"Email Verification OTP is: {otp}";

                //Send Email service
                try
                {
                    await _emailService.SendEmailAsync(model.Email, emailHeader, emailBody);

                    return (true, Array.Empty<string>());
                }
                catch (Exception ex)
                {
                    return (false, new[] { "Failed to send email verification email" });
                }

                //return await SendEmail(model.Email, emailHeader, emailBody);

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

        public async Task<(bool success, IEnumerable<string> Errors)> LogoutUserAsync()
        {
            try
            {
                // Sign out user from Identity system
                await _signInManager.SignOutAsync();

                // If using distributed token invalidation, you could add the token to a blacklist here
                // This would require accessing the token from the HTTP context
                // You'd need to inject IHttpContextAccessor and access the token:
                // var token = _httpContextAccessor.HttpContext.Request.Headers["Authorization"].ToString().Replace("Bearer ", "");
                // Then add this token to a blacklist (Redis, database, etc.)
                // @mafiqqq - Study on this concept

                return (true, Array.Empty<string>());
            }
            catch (Exception ex) {
                return (false, new[] { $"Logout failed: {ex.Message}" });
            }

        }

        public async Task<(bool success, IEnumerable<string> Errors, string token)> LoginUserAsync(LoginDTO model)
        {
            var user = await _userManager.FindByNameAsync(model.Username);

            if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
            {
                if (!user.EmailConfirmed)
                {
                    return (false, new[] { "User has not been verified yet" }, String.Empty);
                }

                // Flow if 2FA enabled
                if (user.TwoFactorEnabled)
                {
                    // Generate and Send OTP
                    var otp = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");

                    // Email the OTP number to user
                    var emailBody = $"<p>To verify your email address click {otp}";
                    var emailHeader = $"Email Verification OTP is: {otp}";


                    await SendEmail(user.Email, emailBody, emailHeader);

                    return (true, Array.Empty<string>(), String.Empty);
                }
                // Flow if 2FA is not enabled
                else
                {
                    var token = await GenerateJwtToken(user);
                    return (true, Array.Empty<string>(), token);
                }
            }

            return (false, new[] { "Failed to login. Invalid username/password" }, String.Empty);
        }

        public async Task<(bool success, IEnumerable<string> Errors, string token)> VerifyOtpAsync(VerifyOtpDTO model)
        {
            var user = await _userManager.FindByIdAsync(model.UserId);
            if (user == null)
            {
                return (false, new[] { "User does not exist." }, String.Empty);
            }

            var isValid = await _userManager.VerifyTwoFactorTokenAsync(
                user, 
                _userManager.Options.Tokens.AuthenticatorTokenProvider, 
                model.Otp);

            if (isValid)
            {
                // Sign-in the user
                await _signInManager.SignInAsync(user, isPersistent: false);

                // Generate JWT and return to user
                var token = await GenerateJwtToken(user);
                return (true, Array.Empty<string>(), token);
            }

            return (false, new[] { "Invalid verification code" }, String.Empty);
        }

        public async Task<(bool success, IEnumerable<string> Errors)> ForgotPasswordAsync(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                return (false, new[] { "Email does not exist" });
            }

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);

            var encodedEmail = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(user.Email));
            var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));

            var resetPasswordLink = string.Format(
                    "{0}?encodedEmail={1}&encodedToken={2}&campaign=reset-password",
                    _configuration["baseUrl"] + "/auth/reset-password",
                    Uri.EscapeDataString(encodedEmail),
                    Uri.EscapeDataString(encodedToken)
                );


            var emailBody = $"<p>To reset your password click <a href='{resetPasswordLink}'>here </a></p>";

            try
            {
                await _emailService.SendEmailAsync(user.Email, "Password reset for PriceTrackr", emailBody);
                return (true, Array.Empty<string>());
            }
            catch (Exception ex)
            {
                return (false, new[] { "Failed to send reset password email" });
            }

            //return await SendEmail(user.Email, "Password reset for PriceTrackr", emailBody);
        }

        public async Task<(bool success, IEnumerable<string> Errors)> ResetPasswordAsync(string email, string token, ResetPasswordDTO model)
        {


            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                return (false, new[] { "User cannot found" });
            }

            var result = await _userManager.ResetPasswordAsync(user, token, model.Password);
            if (result.Succeeded)
            {
                return (true, Array.Empty<string>());
            }
            return (false, new[] { "Failed to reset password" });
        }

        //public async Task<(bool success, IEnumerable<string> Errors)> SendTwoFactorCodeAsync()
        //{ 

        //}

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

        public async Task<(bool success, IEnumerable<string> Errors, string token)> SendEmail(string email, string emailHeader, string emailBody)
        {
            // Send Email service
            try
            {
                await _emailService.SendEmailAsync(email, emailHeader, emailBody);

                return (true, Array.Empty<string>(), String.Empty);
            }
            catch (Exception ex)
            {
                return (false, new[] { "Failed to send email verification email" }, String.Empty);
            }
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

            // What is the diff for this code
            //var claims = new List<Claim>
            //{
            //    new Claim(ClaimTypes.NameIdentifier, user.Id),
            //    new Claim(ClaimTypes.Name, user.UserName),
            //    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            //};

            //claims.AddRange(userRoles.Select(role => new Claim(ClaimTypes.Role, role)));

            //var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
            //var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            //var expires = DateTime.Now.AddMinutes(Convert.ToDouble(_configuration["Jwt:ExpiryMinutes"]));

            //var token = new JwtSecurityToken(
            //    issuer: _configuration["Jwt:Issuer"],
            //    audience: _configuration["Jwt:Audience"],
            //    claims: claims,
            //    expires: expires,
            //    signingCredentials: creds
            //);
            var tokenHandler = new JwtSecurityTokenHandler().WriteToken(token);

            return tokenHandler;
        }

    }
}
