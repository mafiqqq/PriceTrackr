using System.ComponentModel.DataAnnotations;

namespace PriceTrackrAPI.Model.DTO
{
    public class ResetPasswordDTO
    {
        [Required]
        [StringLength(100, MinimumLength = 8)]
        public string Password { get; set; } = String.Empty;
        [Compare("Password", ErrorMessage = "The password and confirmation password do not match")]
        public string ConfirmPassword { get; set; } = String.Empty;
        [EmailAddress]
        public string Email { get; set; } = String.Empty;
        public string Token { get; set; } = String.Empty;    
    }
}
