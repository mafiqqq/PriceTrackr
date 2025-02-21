using System.ComponentModel.DataAnnotations;

namespace PriceTrackrAPI.ViewModel
{
    public class ForgotPasswordViewModel
    {
        [Required]
        [EmailAddress]
        public string email { get; set; } = string.Empty;
    }
}
