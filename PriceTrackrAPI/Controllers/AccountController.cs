using Microsoft.AspNetCore.Mvc;
using PriceTrackrAPI.Model.DTO;
using PriceTrackrAPI.Services.Contract;

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
    }
}
