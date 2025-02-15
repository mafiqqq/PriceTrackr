using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using PriceTrackrAPI.Model.DTO;
using PriceTrackrAPI.Services.Contract;
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
            var baseUrl = $"{Request.Scheme}://{Request.Host}{Url.Action("ConfirmEmail", "Account")}";
            var (success, errors) = await _authService.RegisterUserAsync(model, baseUrl);

            if (success)
            {
                return Ok(new { message = "User registered successfully" });
            }

            return BadRequest(errors);
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDTO model)
        {
            var (success, token) = await _authService.LoginUserAsync(model);

            if (success)
                return Ok(new { token });

            return Unauthorized();
        }

        [HttpGet("confirm-email")]
        public async Task<IActionResult> ConfirmEmail(string encodedEmail, string encodedToken)
        {
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
                    return Ok(new { message = "User email confirmed successfully" });
                }

                return BadRequest(errors);
            }
            catch (FormatException ex)
            {
                //_logger.LogError(ex, "Error decoding email address.");
                return BadRequest("Error decoding email and token:  " + ex.Message); // Or appropriate error response
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

        //[AllowAnonymous]
        //public IActionResult ForgotPassword()
        //{ 

        //}

        [HttpPost("forgot-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ForgotPassword([Required] string email)
        {
            var baseUrl = $"{Request.Scheme}://{Request.Host}{Url.Action("ResetPassword", "Account")}";
            var (success, errors) = await _authService.ForgotPasswordAsync(email, baseUrl);
            if (success)
            {
                return Ok(new { message = "Forgot password email sent successfully" });
            }
            return BadRequest(errors);
        }

        //[HttpGet("reset-password")]


        [HttpPost("reset-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordDTO model)
        { 
            var (success, errors) = await _authService.ResetPasswordAsync(model);
            if (success)
            {
                return Ok(new { message = "Reset password successfully" });
            }
            return BadRequest(errors);
        }

    }
}
