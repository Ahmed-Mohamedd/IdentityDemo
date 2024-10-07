using IdentityApi.Helpers;
using IdentityApi.Services.Interfaces;
using Microsoft.Extensions.Options;
using System.Net.Mail;
using System.Net;

namespace IdentityApi.Services
{
    public class EmailService : IEmailService
    {
        private readonly EmailSetting _email;
        public EmailService(IOptions<EmailSetting> emailSettings)
        {
            _email = emailSettings.Value;
        }
        public async Task SendEmailAsync(string ToEmail, string Subject, string Body, bool IsBodyHtml = false)
        {
            var client = new SmtpClient(_email.MailServer, int.Parse(_email.MailPort))
            {
                Credentials = new NetworkCredential(_email.FromEmail, _email.Password),
                EnableSsl = true,
            };
            MailMessage mailMessage = new MailMessage(_email.FromEmail, ToEmail, Subject, Body)
            {
                IsBodyHtml = IsBodyHtml
            };
            await client.SendMailAsync(mailMessage);
        }
    }
}
