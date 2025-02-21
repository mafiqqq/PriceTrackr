using System.ComponentModel.DataAnnotations;

namespace PriceTrackrAPI.Model
{
    public class ResetPassword
    {
        public string Password { get; set; } = string.Empty;
        public string ConfirmPassword { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string Token { get; set; } = string.Empty;
    }
}
