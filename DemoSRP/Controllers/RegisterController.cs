using Microsoft.AspNetCore.Mvc;
using SRP.Models;
using SRP;
using System.Numerics;

namespace SRP.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class RegisterController : ControllerBase
    {
        private readonly UserDatabase _userDatabase;

        public RegisterController()
        {
            _userDatabase = new UserDatabase();
        }

        [HttpPost]
        public IActionResult Register([FromBody] RegisterRequest request)
        {
            try
            {
                var salt = BigInteger.Parse(request.Salt);
                var verifier = BigInteger.Parse(request.Verifier); // Это v = g^x mod N
                _userDatabase.RegisterUser(request.Username, salt, verifier);
                return Ok(new { Message = "User registered successfully" });
            }
            catch (InvalidOperationException ex)
            {
                return BadRequest(new { Message = ex.Message });
            }
            catch (Exception ex)
            {
                Console.WriteLine("Register error: " + ex.Message);
                return BadRequest(new { Message = "Registration failed: " + ex.Message });
            }
        }
    }
}