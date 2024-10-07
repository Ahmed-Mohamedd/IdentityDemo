﻿using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace IdentityApi.Data
{
    public class IdentityContext:IdentityDbContext
    {
        public IdentityContext(DbContextOptions<IdentityContext> options):base(options)
        {
            
        }
    }
}
