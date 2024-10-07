using IdentityApi.DTOs;
using IdentityApi.Errors;
using IdentityApi.Helpers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace IdentityApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
   

    public class AdminController : ControllerBase
    {
        private readonly RoleManager<IdentityRole> _roleManager;

        public AdminController(RoleManager<IdentityRole> roleManager)
        {
            _roleManager=roleManager;
        }

        
        [HttpGet("roles")]
        public async Task<ActionResult> GetRoles()
        {
            List<IdentityRole> roles = await _roleManager.Roles.ToListAsync();
            return Ok(roles);
        }

        [HttpPost("CreateRole")]
        public async Task<ActionResult> CreateRole([FromBody]RoleDto model)
        {
            if(await AccountHelper.RoleExists(model?.RoleName , _roleManager))
                return BadRequest(new ApiResponse(400 , "Role Already exists"));

            IdentityRole Role = new IdentityRole { Name = model?.RoleName };

            // Saves the role in the underlying AspNetRoles table
            IdentityResult result = await _roleManager.CreateAsync(Role);
            if (result.Succeeded)
            {
                return Ok(new ApiResponse(200 , $"the {Role.Name} role has been created"));
            }
            else
            {
                foreach (IdentityError error in result.Errors)
                {
                    ModelState.AddModelError("", error.Description);
                }
            }
            return BadRequest(ModelState);
        }

        [HttpPost("Edit-role/{id}")]
        public async Task<ActionResult> EditRole([FromRoute]string id , [FromBody] RoleDto model)
        {
            var role = await _roleManager.FindByIdAsync(id);
            if (role == null)
                return BadRequest(new ApiResponse(400, $"role with {id} id is not found"));

            role.Name = model.RoleName;
            var result = await _roleManager.UpdateAsync(role);

            if (result.Succeeded)
                return Ok(new ApiResponse(200, $"role with id:{role.Id} is updated successfully"));

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error.Description);
            }
            return BadRequest(new ApiResponse(400 ,ModelState.ToString()));
        }

        [HttpDelete("delete-role/{id}")]
        public async Task<ActionResult> DeleteRole([FromRoute] string id)
        {
            var role = await _roleManager.FindByIdAsync(id);
            if (role == null)
                return BadRequest(new ApiResponse(400, $"role with {id} id is not found"));

            var result = await _roleManager.DeleteAsync(role);
            if (result.Succeeded)
                return Ok(new ApiResponse(200));
            
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error.Description);
            }
            return BadRequest(new ApiResponse(400, ModelState.ToString())); 
        }

       

    }
}
