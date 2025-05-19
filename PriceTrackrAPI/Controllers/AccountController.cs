using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using PriceTrackrAPI.Model.DTO;
using PriceTrackrAPI.Services.Contract;
using PriceTrackrAPI.ViewModel;
using System.ComponentModel.DataAnnotations;
using System.Text;

namespace PriceTrackrAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly IAuthService _authService;

        public AccountController(IAuthService authService)
        {
            _authService = authService;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDTO model)
        {
            var (success, errors) = await _authService.RegisterUserAsync(model);

            if (success)
            {
                return Ok(new BaseResponseViewModel 
                { 
                    Result = true,
                    Message = "User registered successfully" 
                });
            }

            return BadRequest(new BaseResponseViewModel { 
                Result = false,
                Message = "Registration failed",
                Errors = errors.ToList()
            });
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDTO model)
        {
            var (success, errors, token) = await _authService.LoginUserAsync(model);

            if (success)
            { 
                if (string.IsNullOrEmpty(token))
                {
                    // Create a temp cookie for 2FA flow containing only the username
                    // Set this temp cookie so can identify the user in next step
                    Response.Cookies.Append("X-TwoFactorAuth",
                        model.Username,
                        new CookieOptions
                        {
                            HttpOnly = true,
                            Secure = true,
                            SameSite = SameSiteMode.None,
                            MaxAge = TimeSpan.FromMinutes(10)
                        });

                    return Ok(new AuthResponseViewModel
                    {
                        Token = String.Empty,
                        RequiresTwoFactor = true,
                        Result = true,
                        Message = "OTP Email Verification has been sent."
                    });
                }
                return Ok(new AuthResponseViewModel
                {
                    Token = token,
                    Result = true,
                    Message = "Login Success"
                });
            }

            return Unauthorized(new BaseResponseViewModel
            { 
                Result = false,
                Message = "Authentication Failed",
                Errors = errors.ToList()
            });
        }

        [HttpPost("logout")]
        [Authorize]
        public async Task<IActionResult> Logout()
        {
            var (success, errors) = await _authService.LogoutUserAsync();

            if (success) {
                return Ok(new BaseResponseViewModel
                {
                    Result = true,
                    Message = "Logout successful"
                });
            }

            return BadRequest(new BaseResponseViewModel
            {
                Result = false,
                Message = "Logout failed",
                Errors = errors.ToList()
            });
        }

        [HttpGet("confirm-email")]
        public async Task<IActionResult> ConfirmEmail()
        {

            var encodedEmail = Request.Headers["X-Email"];
            var encodedToken = Request.Headers["X-Token"];
            
            // Decode the email and token
            try
            {
                var decodedEmailBytes = WebEncoders.Base64UrlDecode(encodedEmail);
                var email = Encoding.UTF8.GetString(decodedEmailBytes);

                var decodedTokenBytes = WebEncoders.Base64UrlDecode(encodedToken);
                var token = Encoding.UTF8.GetString(decodedTokenBytes);

                var (success, errors) = await _authService.ConfirmEmailAsync(email, token);

                if (success)
                {
                    return Ok(new BaseResponseViewModel {
                        Result = true,
                        Message = "User email confirmed successfully"
                    });
                }

                return BadRequest(new BaseResponseViewModel { 
                    Result = false,
                    Message = "User email failed to confirm",
                    Errors = errors.ToList()
                });
            }
            catch (FormatException ex)
            {
                //_logger.LogError(ex, "Error decoding email address.");
                return BadRequest(new BaseResponseViewModel
                {
                    Result = false,
                    Message = "Error decoding confirm email",
                    Errors = new List<string> { ex.Message }
                });
            }
        }

        [HttpPost("add-role")]
        public async Task<IActionResult> AddRole([FromBody] string role)
        {
            var (success, errors) = await _authService.AddRoleAsync(role);
            if (success)
                return Ok(new { message = "Role has been added successfully" });

            return BadRequest(errors);
        }

        [HttpPost("assign-role")]
        public async Task<IActionResult> AssignRole([FromBody] UserRoleDTO model)
        {
            var (success, errors) = await _authService.AssignRoleAsync(model);

            if (success)
            {
                return Ok(new { message = "Role Assigned successfully" });
            }
            return BadRequest(errors);
        }

        [HttpPost("verify-otp")]
        public async Task<IActionResult> VerifyOtp([FromBody] VerifyOtpDTO model)
        {
            // Add this debug code before trying to read the cookie
            foreach (var cookie in HttpContext.Request.Cookies)
            {
                System.Diagnostics.Debug.WriteLine($"Cookie: {cookie.Key} = {cookie.Value}");
            }

            // Get the 2FA token from cookie
            if (!HttpContext.Request.Cookies.TryGetValue("X-TwoFactorAuth", out var username))
            {
                return Unauthorized(new BaseResponseViewModel
                {
                    Result = false,
                    Message = "Invalid 2FA session"
                });
            }

            // Call the service to verify OTP
            var (success, errors, token) = await _authService.VerifyOtpAsync(username, model);

            if (!success) {
                return BadRequest(new AuthResponseViewModel
                {
                    Result = false,
                    Message = "Failed to verify OTP",
                    Errors = errors.ToList()
                });
            }

            SetJwtCookie(token);

            // Remove the temp 2FA cookie
            Response.Cookies.Delete("X-TwoFactorAuth", new CookieOptions { 
                HttpOnly= true,
                Secure = true,
                SameSite = SameSiteMode.None
            });

            return Ok(new AuthResponseViewModel
            {
                Result = true,
                RequiresTwoFactor = true,
            });
        }

        [HttpPost("forgot-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordViewModel model)
        {
            var (success, errors) = await _authService.ForgotPasswordAsync(model.email);
            if (success)
            {
                return Ok(new BaseResponseViewModel
                {
                    Message = "Forgot password email sent successfully",
                    Result = true
                });
            }

            return BadRequest(new BaseResponseViewModel { 
                Result = false,
                Message = "Failed to send forgot-password email",
                Errors = errors.ToList()
            });
        }


        [HttpPost("reset-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordDTO model)
        {
            var encodedEmail = Request.Headers["X-Email"];
            var encodedToken = Request.Headers["X-Token"];

            // Decode the email and token
            try
            {
                var decodedEmailBytes = WebEncoders.Base64UrlDecode(encodedEmail);
                var email = Encoding.UTF8.GetString(decodedEmailBytes);

                var decodedTokenBytes = WebEncoders.Base64UrlDecode(encodedToken);
                var token = Encoding.UTF8.GetString(decodedTokenBytes);

                var (success, errors) =  await _authService.ResetPasswordAsync(email, token, model);

                if (success)
                {
                    return Ok(new BaseResponseViewModel
                    {
                        Result = true,
                        Message = "Reset password successfully"
                    });
                }

                return BadRequest(new BaseResponseViewModel
                {
                    Result = false,
                    Message = "Failed to reset password",
                    Errors = errors.ToList()
                });
            }
            catch (FormatException ex)
            {
                //_logger.LogError(ex, "Error decoding email address.");
                return BadRequest(new BaseResponseViewModel
                {
                    Result = false,
                    Message = "Error decoding confirm email",
                    Errors = new List<string> { ex.Message }
                });
            }
        }

        private void SetJwtCookie(string token)
        {
            Response.Cookies.Append("X-AuthToken", token, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.None,
                MaxAge = TimeSpan.FromHours(24)
            });
        }
    }

}
