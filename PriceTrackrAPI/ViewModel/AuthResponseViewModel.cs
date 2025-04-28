namespace PriceTrackrAPI.ViewModel
{
    public class AuthResponseViewModel : BaseResponseViewModel
    {
        public string Token { get; set; } = string.Empty;
        public bool RequiresTwoFactor { get; set; } = false;
        public string UserId { get; set; } = string.Empty;
    }
}
