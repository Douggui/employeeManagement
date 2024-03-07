using BaseLibrary;
using BaseLibrary.DTOs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ServerLibrary.Repositories;

public interface IUserAccount
{
    public Task<GeneralResponse> CreateAsync(Register user);

    public Task<LoginResponse> SignInAsync(Login user);

    public Task<LoginResponse> RefreshTokenAsync(RefreshToken token);
}
