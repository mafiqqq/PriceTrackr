using Microsoft.AspNetCore.Identity;
using PriceTrackrAPI.Model.DTO;
using PriceTrackrAPI.Services.Contract;

namespace PriceTrackrAPI.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<IdentityUser> _userManager;

        public AuthService(UserManager<IdentityUser> userManager)
        {
            _userManager = userManager;
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

    }
}
