using IdentityApi.DTOs;
using IdentityApi.Errors;
using IdentityApi.Helpers;
using IdentityApi.Services.Interfaces;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Facebook;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.MicrosoftAccount;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using System.Data;
using System.Security.Claims;
using System.Text.Encodings.Web;

namespace IdentityApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly ITokenProvider _tokenProvider;
        private readonly IEmailService _emailService;

        public AccountController(RoleManager<IdentityRole> roleManager, SignInManager<IdentityUser> signInManager, UserManager<IdentityUser> userManager, ITokenProvider tokenProvider, IEmailService emailService)
        {
            _roleManager=roleManager;
            _signInManager=signInManager;
            _userManager=userManager;
            _tokenProvider=tokenProvider;
            _emailService=emailService;
        }

        [HttpPost("register")]
        public async Task<ActionResult<UserDto>> Register(RegisterDto model)
        {
            if(ModelState.IsValid)
            {
                if( await AccountHelper.EmailExists(model.Email , _userManager))
                    return BadRequest("there is already an account associated with that email");

                var user = new IdentityUser
                {
                    UserName = model.Username,
                    Email = model.Email
                    
                };

                // Store user data in AspNetUsers database table
                var result = await _userManager.CreateAsync(user , model.Password);

                if (result.Succeeded)
                {
                    await SendConfirmationEmail(user.Email, user); // send confirmation email
                    await _userManager.AddToRoleAsync(user, Roles.User_Role);
                    var userDto = new UserDto()
                    {
                        Username =  model.Username,
                        Email = model.Email,
                        Token = await _tokenProvider.CreateToken(user),
                    };
                    return Ok(userDto);
                }
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
                return BadRequest(ModelState);
            }

            return BadRequest(ModelState);
        }

        [HttpPost("login")]
        public async Task<ActionResult<UserDto>> Login(LoginDto dto)
        {
            if(ModelState.IsValid)
            {
                var user  = await AccountHelper.GetUser(dto.Email, _userManager);
                if (user == null) return Unauthorized(new ApiResponse(401));

                // check for user's email confirmation
                if (!user.EmailConfirmed &&
                    (await _userManager.CheckPasswordAsync(user, dto.Password)))
                {
                     return BadRequest(new ApiResponse(400,"Email not confirmed yet"));
                }
                // The last boolean parameter lockoutOnFailure indicates if the account should be locked on failed login attempt. 
                // On every failed login attempt AccessFailedCount column value in AspNetUsers table is incremented by 1. 
                // When the AccessFailedCount reaches the configured MaxFailedAccessAttempts which in our case is 5,
                // the account will be locked and LockoutEnd column is populated.
                // After the account is lockedout, even if we provide the correct username and password,
                // PasswordSignInAsync() method returns Lockedout result and
                // the login will not be allowed for the duration the account is locked.
                var result = await _signInManager.PasswordSignInAsync(user.UserName , dto.Password , dto.RememberMe , lockoutOnFailure:true);
                if (result.Succeeded)
                {
                    var userDto = new UserDto()
                    {
                        Username =  user.UserName,
                        Email = user.Email,
                        Token = await _tokenProvider.CreateToken(user),
                    };
                    return Ok(userDto);
                }
                if (result.IsLockedOut)
                {
                    // inform users when their account is locked.
                    //This also can be done through the UI or by sending an email notification.
                    await SendAccountLockedEmail(dto.Email);
                    return Unauthorized(new ApiResponse(401,"Account Locked"));
                }
                else
                {
                    var attemptsLeft = _userManager.Options.Lockout.MaxFailedAccessAttempts - await _userManager.GetAccessFailedCountAsync(user);
                    return BadRequest(new ApiResponse(400, $"Invalid Login Attempt. Remaining Attempts : {attemptsLeft}"));
                }
            }
            return BadRequest(ModelState);
        }

        [HttpGet("login-google")]
        public async Task<ActionResult>  SignInGoogle(string returnUrl = "/")
        {
            var redirecturl = Url.Action(nameof(signin_google) , "Account" , values: new { returnUrl });
            var properties =  _signInManager.ConfigureExternalAuthenticationProperties(GoogleDefaults.AuthenticationScheme , redirecturl);
            return Challenge(properties ,GoogleDefaults.AuthenticationScheme );
          
        }

        [HttpGet("GoogleLoginCallback")]
        public async Task<ActionResult> signin_google(string returnUrl = "/")
        {
            returnUrl = returnUrl ?? Url.Content("~/");
            // Get the login information about the user from the external login provider
            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
                return Unauthorized(new ApiResponse(401));

            // If the user already has a login ( if there is a record in AspNetUserLogins table)
            // then user 'll sign-in  with this external login provider
            var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider,
                                                  info.ProviderKey, isPersistent: false, bypassTwoFactor: true);
            if (result.Succeeded)
                return Ok(new ApiResponse(200));

            // If there is no record in AspNetUserLogins table, the user may not have a local account

            // Get the email claim value
            var email = info.Principal.FindFirstValue(ClaimTypes.Email);
            if (email != null)
            {
                // Create a new user without password if we do not have a user already
                var user = await _userManager.FindByEmailAsync(email);
                if (user == null)
                {
                    user = new IdentityUser
                    {
                        UserName = email.Split("@")[0],
                        Email = email
                    };
                    //This will create a new user into the AspNetUsers table without password
                    await _userManager.CreateAsync(user);

                }
                // Add a login (i.e., insert a row for the user in AspNetUserLogins table)
                await _userManager.AddLoginAsync(user, info);
                //Then Signin the User
                await _signInManager.SignInAsync(user, isPersistent: false);
                return Ok(new ApiResponse(200));
            }
            return BadRequest(new ApiResponse(400));
        }


        [HttpGet("login-microsoft")]
        public async Task<ActionResult> LoginMicrosoft(string returnUrl = "/")
        {
            var redirectUrl = Url.Action(nameof(MicrosoftLoginCallback), "Account", new { returnUrl });
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(MicrosoftAccountDefaults.AuthenticationScheme, redirectUrl);
            return Challenge(properties, MicrosoftAccountDefaults.AuthenticationScheme);
        }

        [HttpGet("signin-microsoft")]
        public async Task<ActionResult> MicrosoftLoginCallback(string returnUrl = "/")
        {
            returnUrl = returnUrl ?? Url.Content("~/");
            // Get the login information about the user from the external login provider
            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
                return Unauthorized(new ApiResponse(401));

            // If the user already has a login( if there is a record in AspNetUserLogins table)
            // then user 'll sign-in  with this external login provider
            var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider,info.ProviderKey, isPersistent: false, bypassTwoFactor: true);
            if (result.Succeeded)
                return Ok(new ApiResponse(200 , "Login is Successful."));

            // If there is no record in AspNetUserLogins table, the user may not have a local account
            // Get the email claim value
            var email = info.Principal.FindFirstValue(ClaimTypes.Email);
            if (email != null)
            {
                // Create a new user without password if we do not have a user already
                var user = await _userManager.FindByEmailAsync(email);
                if (user == null)
                {
                    user = new IdentityUser
                    {
                        UserName = email.Split("@")[0],
                        Email = email
                    };
                    //This will create a new user into the AspNetUsers table without password
                    await _userManager.CreateAsync(user);

                }
                // Add a login (i.e., insert a row for the user in AspNetUserLogins table)
                await _userManager.AddLoginAsync(user, info);
                //Then Signin the User
                await _signInManager.SignInAsync(user, isPersistent: false);
                return Ok(new ApiResponse(200));
            }
            return BadRequest(new ApiResponse(400));
        }

        [HttpGet("login-facebook")]
        public async Task<ActionResult> LoginFacebook(string returnUrl = "/")
        {
            var redirectUrl = Url.Action(nameof(FacebookLoginCallback), "Account", new { returnUrl });
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(FacebookDefaults.AuthenticationScheme, redirectUrl);
            return Challenge(properties, FacebookDefaults.AuthenticationScheme);
        }

        [HttpGet("signin-facebook")]
        public async Task<ActionResult> FacebookLoginCallback(string returnUrl = "/")
        {
            returnUrl = returnUrl ?? Url.Content("~/");
            // Get the login information about the user from the external login provider
            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
                return Unauthorized(new ApiResponse(401));

            // If the user already has a login( if there is a record in AspNetUserLogins table)
            // then user 'll sign-in  with this external login provider
            var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false, bypassTwoFactor: true);
            if (result.Succeeded)
                return Ok(new ApiResponse(200, "Login is Successful."));

            // If there is no record in AspNetUserLogins table, the user may not have a local account
            // Get the email claim value
            var email = info.Principal.FindFirstValue(ClaimTypes.Email);
            if (email != null)
            {
                // Create a new user without password if we do not have a user already
                var user = await _userManager.FindByEmailAsync(email);
                if (user == null)
                {
                    user = new IdentityUser
                    {
                        UserName = email.Split("@")[0],
                        Email = email
                    };
                    //This will create a new user into the AspNetUsers table without password
                    await _userManager.CreateAsync(user);

                }
                // Add a login (i.e., insert a row for the user in AspNetUserLogins table)
                await _userManager.AddLoginAsync(user, info);
                //Then Signin the User
                await _signInManager.SignInAsync(user, isPersistent: false);
                return Ok(new ApiResponse(200));
            }
            return BadRequest(new ApiResponse(400));
        }


        [HttpGet("ConfirmEmail")]
        [AllowAnonymous]
        public async Task<ActionResult> ConfirmEmail([FromQuery]string UserId,[FromQuery] string Token)
        {
            if (UserId == null || Token == null)
            {
                return BadRequest(new ApiResponse( 400,"The link is Invalid or Expired"));
            }

            //Find the User By Id
            var user = await _userManager.FindByIdAsync(UserId);
            if (user == null)
            {
                return BadRequest(new ApiResponse(400, $"The User ID {UserId} is Invalid"));
            }

            //Call the ConfirmEmailAsync Method which will mark the Email as Confirmed
            var result = await _userManager.ConfirmEmailAsync(user, Token);
            if (result.Succeeded)
                return Ok(new ApiResponse(200,"Thank you for confirming your email"));

            return BadRequest(new ApiResponse(400,"Email cannot be confirmed"));
        }
        private async Task SendConfirmationEmail(string? email, IdentityUser? user)
        {
            //Generate the Token
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            //Build the Email Confirmation Link which must include the Callback URL
            var ConfirmationLink = Url.Action("ConfirmEmail", "Account",
            new { UserId = user.Id, Token = token }, protocol: HttpContext.Request.Scheme);
            //Send the Confirmation Email to the User Email Id
            await _emailService.SendEmailAsync(email, "Confirm Your Email", $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(ConfirmationLink)}'>clicking here</a>.", true);
        }

        [HttpPost("ResendConfirmationEmail")]
        [AllowAnonymous]
        public async Task<ActionResult> ResendConfirmationEmail(string Email)
        {
            var user = await _userManager.FindByEmailAsync(Email);

                // Handling the situation when the user does not exist or Email already confirmed.
            if (user == null || await _userManager.IsEmailConfirmedAsync(user))
            {
                // For security, we 'll not reveal that the user does not exist or Email is already confirmed
                return BadRequest(new ApiResponse(400 , "an error occured during confirmation operation!. try again after  a few minnutes"));
            }
            //Then send the Confirmation Email to the User
            await SendConfirmationEmail(Email, user);
            return Ok(new ApiResponse(200 , "Confirmation email has been sent."));
        }

        [HttpPost("ForgetPassword")]
        [AllowAnonymous]
        public async Task<ActionResult> ForgotPassword([FromBody] string email)
        {
            if (ModelState.IsValid)
            {
                // Find the user by email
                var user = await _userManager.FindByEmailAsync(email);
                // If the user is found AND Email is confirmed
                if (user != null && await _userManager.IsEmailConfirmedAsync(user))
                {
                    await SendForgotPasswordEmail(user.Email, user);
                    // Send the user to Forgot Password Confirmation view
                    return Ok(new ApiResponse(200,"we have sent an email with instruction to reset your password"));
                }
                // we avoid account enumeration and brute force attacks, so we don't
                // reveal that the user does not exist or is not confirmed
                return BadRequest(new ApiResponse(400,"An error happened"));
            }
            return BadRequest(new ApiResponse(400));
        }

        private async Task SendForgotPasswordEmail(string? email, IdentityUser? user)
        {
            // Generate the reset password token
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);

            //save the token into the AspNetUserTokens database table
            await _userManager.SetAuthenticationTokenAsync(user, "ResetPassword", "ResetPasswordToken", token);

            // Build the password reset link which must include the Callback URL
            var passwordResetLink = Url.Action("ResetPassword", "Account",
                    new { Email = email, Token = token }, protocol: HttpContext.Request.Scheme);
            //Send the Confirmation Email to the User Email Id
            await _emailService.SendEmailAsync(email, "Reset Your Password", $"Please reset your password by <a href='{HtmlEncoder.Default.Encode(passwordResetLink)}'>clicking here</a>.", true);
        }

        [HttpPost("ResetPassword")]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword(ResetPasswordDto model)
        {
            if (ModelState.IsValid)
            {
                // Find the user by email
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user != null)
                {
                    // reset the user password
                    var result = await _userManager.ResetPasswordAsync(user, model.Token, model.Password);
                    if (result.Succeeded)
                    {
                        // Upon successful password reset and if the account is lockedout,
                        // set the account lockout end date to current UTC date time, 
                        // so the user can login with the new password
                        if (await _userManager.IsLockedOutAsync(user))
                        {
                            await _userManager.SetLockoutEndDateAsync(user, DateTimeOffset.UtcNow);
                        }

                        //Once the Password is Reset, remove the token from the database
                        await _userManager.RemoveAuthenticationTokenAsync(user, "ResetPassword", "ResetPasswordToken");
                        return Ok(new ApiResponse(200,"Reset Password Confirmed successfully"));
                    }
                    // Display validation errors. For example, password reset token already
                    // used to change the password or password complexity rules not met
                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError("", error.Description);
                    }
                    return BadRequest(new ApiResponse(400,ModelState.ToString()));
                }
                // To avoid account enumeration and brute force attacks, 
                // reveal that the user does not exist
                return BadRequest(new ApiResponse(400, "error occurred while resetting"));
            }
            // Display validation errors if model state is not valid
            return BadRequest(new ApiResponse(400, ModelState.ToString()));
        }

        [Authorize]
        [HttpPost("change-password")]
        public async Task<ActionResult> ChangePassword(ChangePasswordDto model)
        {
            if(ModelState.IsValid)
            {
                var username = User.FindFirstValue(ClaimTypes.NameIdentifier);
                var user = await _userManager.FindByNameAsync(username);
                if (user == null) 
                    return Unauthorized(new ApiResponse(401));

                // ChangePasswordAsync Method changes the user password
                var result = await _userManager.ChangePasswordAsync(user, model.OldPassword, model.NewPassword);

                // if The new password did not meet the complexity rules or the current password is incorrect.
                //we 'll Add these errors to the ModelState and rerender ChangePassword view
                if (!result.Succeeded)
                {
                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError(string.Empty, error.Description);
                    }
                    return BadRequest(new ApiResponse(400));
                }
                // Upon successfully changing the password refresh sign-in cookie
                await _signInManager.RefreshSignInAsync(user);
                return Ok(new ApiResponse(200));
            }
            return BadRequest(new ApiResponse(400));
        }

        [Authorize]
        [HttpPost("AddPasswordFor-ExternalLoginUser")]
        public async Task<ActionResult> AddPassword(AddPasswordDto model)
        {
            var username = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var user = await _userManager.FindByNameAsync(username);
            if (await _userManager.HasPasswordAsync(user))
                return BadRequest(new ApiResponse(400, "user's account already has a password"));

            if (ModelState.IsValid)
            {
                if (user == null)
                    return Unauthorized(new ApiResponse(401));

                //Call the AddPasswordAsync method to set the new password without old password
                var result = await _userManager.AddPasswordAsync(user, model.NewPassword);
                // Handle the failure scenario
                if (!result.Succeeded)
                {
                    string error ="";
                    //fetch all the error messages and display on the view
                    foreach (var e in result.Errors)
                    {
                        error += e.Description;
                    }
                    return BadRequest(new ApiResponse(400, error));
                }
                // Handle Success Scenario
                // refresh the authentication cookie to store the updated user information
                await _signInManager.RefreshSignInAsync(user);

                return Ok(new ApiResponse(200, "password Added successfully"));
            }
            return BadRequest(new ApiResponse(400));
        }

        private async Task SendAccountLockedEmail(string? email)
        {
            //Send the Confirmation Email to the User Email Id
            await _emailService.SendEmailAsync(email, "Account Locked", "Your Account is Locked Due to Multiple Invalid Attempts.", false);
        }


    }
}
