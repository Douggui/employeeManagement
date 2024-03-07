using BaseLibrary.DTOs;
using BaseLibrary;
using Microsoft.AspNetCore.Mvc;
using ServerLibrary.Repositories;



namespace Server.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AuthenticationController(IUserAccount userAccount) : ControllerBase
{
    [HttpPost("register")]
    public async Task<IActionResult> CreateUser(Register user)
    {
        if (user == null)
            return BadRequest("Model is empty");
        GeneralResponse result = await userAccount.CreateAsync(user); 
        return Ok(result);
    }

    [HttpPost("login")]
    public async Task<IActionResult> SignIn(Login user)
    {
        if (user == null)
            return BadRequest("Model is empty");

        var result = await userAccount.SignInAsync(user);
        return Ok(result);

    }

    [HttpPost("refresh-token")]
    public async Task<IActionResult> RefreshToken(RefreshToken token)
    {
        if (token == null) 
            return BadRequest( "Model is emplty");

        LoginResponse result = await userAccount.RefreshTokenAsync(token);
        return Ok(result);
    }
}
