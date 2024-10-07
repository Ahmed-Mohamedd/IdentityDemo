using System.ComponentModel.DataAnnotations;

namespace IdentityApi.DTOs
{
    public class RoleDto
    {
        [Required]
        [Display(Name = "Role")]
        public string RoleName { get; set; }
    }

}
