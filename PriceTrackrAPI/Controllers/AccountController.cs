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
                return Ok(new AuthResponseViewModel 
                { 
                    Result = true,
                    Message = "User registered successfully" 
                });
            }

            return BadRequest(new AuthResponseViewModel { 
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
                return Ok(new AuthResponseViewModel 
                {
                    Token = token,
                    Result = true,
                    Message = "Login Success"
                });
            }

            return Unauthorized(new AuthResponseViewModel
            { 
                Result = false,
                Message = "Authentication Failed",
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
                    return Ok(new AuthResponseViewModel {
                        Result = true,
                        Message = "User email confirmed successfully"
                    });
                }

                return BadRequest(new AuthResponseViewModel { 
                    Result = false,
                    Message = "User email failed to confirm",
                    Errors = errors.ToList()
                });
            }
            catch (FormatException ex)
            {
                //_logger.LogError(ex, "Error decoding email address.");
                return BadRequest(new AuthResponseViewModel
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

        [HttpPost("forgot-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordViewModel model)
        {
            var (success, errors) = await _authService.ForgotPasswordAsync(model.email);
            if (success)
            {
                return Ok(new AuthResponseViewModel
                {
                    Message = "Forgot password email sent successfully",
                    Result = true
                });
            }

            return BadRequest(new AuthResponseViewModel { 
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
                    return Ok(new AuthResponseViewModel
                    {
                        Result = true,
                        Message = "Reset password successfully"
                    });
                }

                return BadRequest(new AuthResponseViewModel
                {
                    Result = false,
                    Message = "Failed to reset password",
                    Errors = errors.ToList()
                });
            }
            catch (FormatException ex)
            {
                //_logger.LogError(ex, "Error decoding email address.");
                return BadRequest(new AuthResponseViewModel
                {
                    Result = false,
                    Message = "Error decoding confirm email",
                    Errors = new List<string> { ex.Message }
                });
            }
        }

    }
}
