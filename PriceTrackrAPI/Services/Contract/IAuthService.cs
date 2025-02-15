using PriceTrackrAPI.Model.DTO;

namespace PriceTrackrAPI.Services.Contract
{
    public interface IAuthService
    {
        Task<(bool success, IEnumerable<string> Errors)> RegisterUserAsync(RegisterDTO model, string baseUrl);
        Task<(bool success, string token)> LoginUserAsync(LoginDTO model);
        Task<(bool success, IEnumerable<string> Errors)> AddRoleAsync(string role);
        Task<(bool success, IEnumerable<string> Errors)> AssignRoleAsync(UserRoleDTO model);
        Task<(bool success, IEnumerable<string> Errors)> ConfirmEmailAsync(string email, string token);
    }
}
