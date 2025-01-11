using System.ComponentModel.DataAnnotations;

namespace PriceTrackrAPI.Model.DTO
{
    public class UserRoleDTO
    {
        [Required]
        public string Username { get; set; } = String.Empty;
        [Required]
        public string Role { get; set; } = String.Empty;
    }
}
