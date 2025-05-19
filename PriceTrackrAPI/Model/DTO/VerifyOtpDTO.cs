using System.ComponentModel.DataAnnotations;

namespace PriceTrackrAPI.Model.DTO
{
    public class VerifyOtpDTO
    {
        [Required]
        [StringLength(6)]
        public string Otp { get; set; } = String.Empty;
    }
}
