using AuthenticationAuthorizationJWT.Authorization;
using AuthenticationAuthorizationJWT.Properties;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace AuthenticationAuthorizationJWT.Controllers
{
	[ApiController]
	[Route("api/Authentication")]
	public class AuthenticationController : ControllerBase
	{
		private readonly UserManager<ApplicationUser> userManager;
		private readonly RoleManager<IdentityRole> roleManager;
		private readonly IConfiguration configuration;

		public AuthenticationController(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
		{
			this.userManager = userManager;
			this.roleManager = roleManager;
			this.configuration = configuration;
		}

		[HttpPost]
		[Route("Register")]
		public async Task<IActionResult> Register([FromBody] RegisterModel model)
		{
			var userExist = await userManager.FindByNameAsync(model.UserName);
			if (userExist != null)
			{
				return StatusCode(StatusCodes.Status500InternalServerError, new Response { Message = "User already exist", Status = "Error" });
			}
			ApplicationUser user = new ApplicationUser()
			{
				Email = model.Email,
				UserName = model.UserName,
				SecurityStamp = Guid.NewGuid().ToString()
			};

			var result = await userManager.CreateAsync(user, model.Password);
			if (!result.Succeeded)
			{
				return StatusCode(StatusCodes.Status500InternalServerError, new Response { Message = "User creation failed", Status = "Error" });
			}
			else
			{
				return Ok(new Response() { Status = "Success", Message = "User created" });
			}
		}

		[HttpPost]
		[Route("RegisterAdmin")]
		public async Task<IActionResult> RegisterAdmin([FromBody] RegisterModel model)
		{
			var userExist = await userManager.FindByNameAsync(model.UserName);
			if (userExist != null)
			{
				return StatusCode(StatusCodes.Status500InternalServerError, new Response { Message = "User already exist", Status = "Error" });
			}
			ApplicationUser user = new ApplicationUser()
			{
				Email = model.Email,
				UserName = model.UserName,
				SecurityStamp = Guid.NewGuid().ToString()
			};

			var result = await userManager.CreateAsync(user, model.Password);
			if (!result.Succeeded)
			{
				return StatusCode(StatusCodes.Status500InternalServerError, new Response { Message = "User creation failed", Status = "Error" });
			}

			if (!await roleManager.RoleExistsAsync(UserRoles.Admin))
			{
				await roleManager.CreateAsync(new IdentityRole(UserRoles.Admin));
			}

			if (!await roleManager.RoleExistsAsync(UserRoles.User))
			{
				await roleManager.CreateAsync(new IdentityRole(UserRoles.User));
			}

			if (await roleManager.RoleExistsAsync(UserRoles.Admin))
			{
				await userManager.AddToRoleAsync(user, UserRoles.Admin);
			}

			return Ok(new Response() { Status = "Success", Message = "User created" });
		}


		[HttpPost]
		[Route("Login")]
		public async Task<IActionResult> LoginUser([FromBody] LoginModel model)
		{
			var user = await userManager.FindByNameAsync(model.UserName);
			if (user != null && await userManager.CheckPasswordAsync(user, model.Password))
			{
				var userRoles = await userManager.GetRolesAsync(user);
				var authClaims = new List<Claim>()
				{
					new Claim(ClaimTypes.Name, user.UserName),
					new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
				};

				foreach (var role in userRoles)
				{
					authClaims.Add(new Claim(ClaimTypes.Role, role));
				}

				var authSignKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JWT:Secret"]));
				var token = new JwtSecurityToken(
						issuer: configuration["JWT:ValidIssuer"],
						audience: configuration["JWT:ValidAudience"],
						expires: DateTime.Now.AddHours(5),
						claims: authClaims,
						signingCredentials: new SigningCredentials(authSignKey, SecurityAlgorithms.HmacSha256)
					);

				return Ok(new
				{
					token = new JwtSecurityTokenHandler().WriteToken(token)
				});

			}

			return Unauthorized();

		}
	}
}
