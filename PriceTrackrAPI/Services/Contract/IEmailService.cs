namespace PriceTrackrAPI.Services.Contract
{
    public interface IEmailService
    {
        Task SendEmailAsync(string to, string subject, string body);
    }
}
