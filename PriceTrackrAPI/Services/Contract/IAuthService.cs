using PriceTrackrAPI.Model.DTO;

namespace PriceTrackrAPI.Services.Contract
{
    public interface IAuthService
    {
        Task<(bool success, IEnumerable<string> Errors)> RegisterUserAsync(RegisterDTO model);
        Task<(bool success, IEnumerable<string> Errors, string token)> LoginUserAsync(LoginDTO model);
        Task<(bool success, IEnumerable<string> Errors)> AddRoleAsync(string role);
        Task<(bool success, IEnumerable<string> Errors)> AssignRoleAsync(UserRoleDTO model);
        Task<(bool success, IEnumerable<string> Errors)> ConfirmEmailAsync(string email, string token);
        Task<(bool success, IEnumerable<string> Errors)> ForgotPasswordAsync(string email);
        Task<(bool success, IEnumerable<string> Errors)> ResetPasswordAsync(string email, string token, ResetPasswordDTO model);
    }
}
