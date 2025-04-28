using System.ComponentModel.DataAnnotations;

namespace PriceTrackrAPI.Model.DTO
{
    public class VerifyOtpDTO
    {
        [Required]
        public string UserId { get; set; } = String.Empty;

        [Required]
        [StringLength(6)]
        public string Otp { get; set; } = String.Empty;
    }
}
