using Azure;
using BaseLibrary;
using BaseLibrary.DTOs;
using BaseLibrary.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using ServerLibrary.Data;
using ServerLibrary.Helpers;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace ServerLibrary.Repositories;

public class UserAccountRepository(AppDBContext context, IOptions<JwtSection> config) : IUserAccount
{
    public async Task<GeneralResponse> CreateAsync(Register user)
    {
        if (user == null ) return new GeneralResponse(false, "Model is empty");

        var checkUser = await FindUserByEmail(user.Email!);

        if (checkUser != null) return new GeneralResponse(false, "User registred already");

        ApplicationUser newUser = new ApplicationUser()
        {
            Name = user.FullName,
            Email = user.Email,
            Password = BCrypt.Net.BCrypt.HashPassword(user.Password)
        };
        
        await context.AddAsync(newUser);
        await context.SaveChangesAsync().ConfigureAwait(false);

        SystemRole? checkAdminRole = await context.SystemRoles.FirstOrDefaultAsync(role => role.Name!.Equals(Constants.Admin));
        if(checkAdminRole == null)
        {
          
            var role = (await context.AddAsync(new SystemRole()
            {
                Name = Constants.Admin
            })).Entity;

            await context.SaveChangesAsync().ConfigureAwait(false);
            await context.AddAsync(new UserRole()
            {
                RoleId = role.Id,
                UserId = newUser.Id,
            });
            await context.SaveChangesAsync().ConfigureAwait(false);
            return new GeneralResponse(true, "User has been registered");
        }
        var checkUserRole = await context.SystemRoles.FirstOrDefaultAsync(role => role.Name!.Equals(Constants.User));
      
        if(checkUserRole == null)
        {
           var response = (await context.AddAsync(new SystemRole()
            {
                Name = Constants.User
            }).ConfigureAwait(false)).Entity;
            await context.SaveChangesAsync().ConfigureAwait(false);
            await context.AddAsync(new UserRole()
            {

                RoleId = response.Id,
                UserId = newUser.Id,
            });
            await context.SaveChangesAsync().ConfigureAwait (false);
        }
        else
        {
            await context.AddAsync(new UserRole()
            {
                RoleId = checkUserRole.Id,
                UserId = newUser.Id,
            });
            await context.SaveChangesAsync(true).ConfigureAwait(false);
        }
        return new GeneralResponse(true, "User has been registered");

    }
    public async Task<LoginResponse> SignInAsync(Login user)
    {
        if (user == null)
            return new LoginResponse(false, "Model is emplty");

        ApplicationUser? appUser = await FindUserByEmail(user.Email!);
        if (appUser == null)
            return new LoginResponse(false, "User not Found");

        if (!BCrypt.Net.BCrypt.Verify(user.Password, appUser.Password))
            return new LoginResponse(false, "Email/Password not valid");

        UserRole? getUserRole = await FindUserRole(appUser.Id);
        if (getUserRole == null)
            return new LoginResponse(false, "User role not found");

        SystemRole? getRoleName = await FindRoleName(getUserRole.RoleId);
        if (getRoleName == null)
            return new LoginResponse(false, "Role not found");


        string jwstToken = GenerateToken(appUser, getRoleName.Name!);
        string refreshToken = GenerateRefreshToken();
        RefreshTokenInfo? token = await context.RefreshTokenInfos.FirstOrDefaultAsync(token => token.UserId == appUser.Id);
        if(token != null)
        {
            token.Token = refreshToken;
            await context.SaveChangesAsync();
        }
        else
        {
            RefreshTokenInfo newRefreshToken = new RefreshTokenInfo()
            {
                Token = refreshToken,
                UserId = appUser.Id,
            };
            await context.SaveChangesAsync();
        }
        return new LoginResponse(true, "Login successfully", jwstToken, refreshToken);
    }

  
    private async Task<ApplicationUser?> FindUserByEmail(string email)
    {
        return  await context.ApplicationUsers.FirstOrDefaultAsync(user => user.Email!.ToLower().Equals(email.ToLower()));
      
    }
    
    private string GenerateToken(ApplicationUser appUser, string roleName)
    {
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config.Value.Key!));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
        Claim[] userClaims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, appUser.Id.ToString()),
            new Claim(ClaimTypes.Name,appUser.Name!),
            new Claim(ClaimTypes.Email, appUser.Email!),
            new Claim(ClaimTypes.Role, roleName)

        };

        JwtSecurityToken token = new JwtSecurityToken(
            issuer: config.Value.Issuer,
            audience: config.Value.Audience,
            claims: userClaims,
            expires:DateTime.Now.AddDays(1),
            signingCredentials: credentials
         ) ;

        return new JwtSecurityTokenHandler().WriteToken(token);

    }

    private static string GenerateRefreshToken() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));

    private async Task<UserRole?> FindUserRole(int userId)
    {
        return await context.UserRoles.FirstOrDefaultAsync(userRole =>  userRole.UserId == userId);
    }

    private async Task<SystemRole?> FindRoleName(int roleId)
    {
        return await context.SystemRoles.FirstOrDefaultAsync(sysRole => sysRole.Id == roleId);
    }

    public async Task<LoginResponse> RefreshTokenAsync(RefreshToken token)
    {
        if (token == null) return new LoginResponse(false, "Model is emplty");

        RefreshTokenInfo? findToken = await context.RefreshTokenInfos.FirstOrDefaultAsync(token => token.Token!.Equals(token.Token));
        if (findToken == null) return new LoginResponse(false, "Refresh token is required");

        ApplicationUser? user = await context.ApplicationUsers.FirstOrDefaultAsync(user => user.Id == findToken.UserId);
        if (user == null) return new LoginResponse(false, "Refresh token could not be generated besause user is not found");

        UserRole? userRole = await FindUserRole(user.Id);
        SystemRole? roleName = await FindRoleName(userRole!.RoleId);

        string jwtToken = GenerateToken(user, roleName!.Name!);
        string refreshToken = GenerateRefreshToken();

        RefreshTokenInfo? updatedRefreshToken = await context.RefreshTokenInfos.FirstOrDefaultAsync(token => token.UserId == user.Id);
        if (updatedRefreshToken == null) return new LoginResponse(false, "Refresh token could not be generated because user has not signed in");

        updatedRefreshToken.Token = refreshToken;
        await context.SaveChangesAsync();
        return new LoginResponse(true, "Token  refreshed successfully", jwtToken, refreshToken);

    }
}
