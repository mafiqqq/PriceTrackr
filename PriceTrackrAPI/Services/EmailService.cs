using MailKit.Net.Smtp;
using MimeKit;
using PriceTrackrAPI.Services.Contract;

namespace PriceTrackrAPI.Services
{
    public class EmailService : IEmailService
    {
        private readonly IConfiguration _configuration;

        public EmailService(IConfiguration configuration) 
        {
            _configuration = configuration;
        }

        public async Task SendEmailAsync(string to, string subject, string body)
        {
            var message = new MimeMessage();
            message.From.Add(new MailboxAddress(_configuration["Email:Sender"], _configuration["Email:SenderEmail"]));
            message.To.Add(new MailboxAddress("", to));
            message.Subject = subject;

            // Set the email body (you can use TextPart for plain text or HtmlPart for HTML)
            var bodyBuilder = new BodyBuilder();
            bodyBuilder.HtmlBody = body;
            message.Body = bodyBuilder.ToMessageBody();

            using (var client = new SmtpClient())
            {

                // Configs of SMTP server
                var smtpServer = _configuration["Email:Host"];
                var smtpPort = int.Parse(_configuration["Email:Port"]!);

                // Connect to SMTP Server (papercut for dev)
                await client.ConnectAsync(smtpServer, smtpPort, false); // No SSL/TLS but in Production need change

                await client.SendAsync(message);
                await client.DisconnectAsync(true);
            }
        }
    }
}
