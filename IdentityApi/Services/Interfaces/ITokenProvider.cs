
using Microsoft.AspNetCore.Identity;

namespace IdentityApi.Services.Interfaces
{
    public interface ITokenProvider
    {
        Task<string> CreateToken(IdentityUser user);
    }
}
