using Microsoft.AspNetCore.Identity;

namespace IdentityApi.Helpers
{
    public static class AccountHelper
    {

        public async static Task<bool> EmailExists(string email , UserManager<IdentityUser> userManager)
        {
            var user = await userManager.FindByEmailAsync(email);
            if (user == null) 
                return false;
            return true;
        }
        public async static Task<IdentityUser?> GetUser(string email, UserManager<IdentityUser> userManager)
           =>  await userManager.FindByEmailAsync(email);

        public async static Task<bool> RoleExists(string RoleName, RoleManager<IdentityRole> roleManager)
            => await roleManager.RoleExistsAsync(RoleName);
         
    }
}
