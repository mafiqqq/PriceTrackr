using PriceTrackrAPI.Model.DTO;

namespace PriceTrackrAPI.Services.Contract
{
    public interface IAuthService
    {
        Task<(bool success, IEnumerable<string> Errors)> RegisterUserAsync(RegisterDTO model);
    }
}
