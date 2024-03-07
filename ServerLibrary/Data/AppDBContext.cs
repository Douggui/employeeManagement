using BaseLibrary.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Identity.Client;

namespace ServerLibrary.Data;

public class AppDBContext(DbContextOptions options) : DbContext(options)
{
    //public AppDBContext(DbContextOptions options) : base(options)
    //{  
    //    public DbSet<Employee> Employees {  get; set; } 
    // }
    //public AppDBContext(DbContextOptions options) : base(options)
    //{
    //}
    //protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    //{
    //    IConfigurationRoot configuration = new ConfigurationBuilder().AddJsonFile(".\\Serverappsettings.json").Build();
    //    optionsBuilder.UseSqlServer(configuration.GetConnectionString("DefaultConnection"));
    //}
    public DbSet<Employee> Employees { get; set; }
    public DbSet<Departement> Departements { get; set; }
    public DbSet<GeneralDepartement> GeneralDepartements { get; set; }
    public DbSet<Branch> Branches { get; set; }
    public DbSet<Town> Towns { get; set; }
    public DbSet<ApplicationUser> ApplicationUsers { get; set; }
    public DbSet<SystemRole> SystemRoles { get; set; }
    public DbSet<UserRole> UserRoles { get; set; }  

    public DbSet<RefreshTokenInfo> RefreshTokenInfos { get; set; }
}
