namespace PriceTrackrAPI.ViewModel
{
    public class BaseResponseViewModel
    {
        public bool Result { get; set; }
        public string Message { get; set; } = string.Empty;
        public List<string> Errors { get; set; } = new List<string>();
    }
}
