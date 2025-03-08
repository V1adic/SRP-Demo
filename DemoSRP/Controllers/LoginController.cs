using Microsoft.AspNetCore.Mvc;
using SRP.Models;
using SRP;
using System.Numerics;
using Microsoft.AspNetCore.Http;

namespace SRP.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class LoginController : ControllerBase
    {
        private readonly UserDatabase _userDatabase;
        private const string ServerBKey = "ServerB";
        private const string ServerSaltKey = "ServerSalt";
        private const string ServerUsernameKey = "ServerUsername";
        private const string ServerVerifierKey = "ServerVerifier";
        private const string ServerPrivateBKey = "ServerPrivateB";

        public LoginController(UserDatabase userDatabase)
        {
            _userDatabase = userDatabase;
        }

        [HttpPost]
        [Route("register")]
        public IActionResult Register([FromBody] RegisterRequest request)
        {
            try
            {
                var salt = BigInteger.Parse(request.Salt);
                var verifier = BigInteger.Parse(request.Verifier);
                _userDatabase.RegisterUser(request.Username, salt, verifier);
                return Ok(new { Message = "User registered successfully" });
            }
            catch (Exception ex)
            {
                return BadRequest(new { Message = "Registration failed: " + ex.Message });
            }
        }

        [HttpPost("start")]
        public IActionResult StartLogin([FromBody] LoginRequest request)
        {
            var userData = _userDatabase.GetUserData(request.Username);

            // Фиктивные значения для несуществующего пользователя
            BigInteger dummySalt = BigInteger.Parse("12345678901234567890123456789012"); // Пример фиксированной соли
            BigInteger dummyVerifier = BigInteger.Parse("9876543210987654321098765432109876543210"); // Пример фиксированного верификатора

            // Выбираем данные в зависимости от наличия пользователя
            BigInteger salt = userData.HasValue ? userData.Value.Salt : dummySalt;
            BigInteger verifier = userData.HasValue ? userData.Value.Verifier : dummyVerifier;

            // Всегда выполняем полный цикл SRP независимо от существования пользователя
            var server = new SrpServer(request.Username, salt, verifier);
            var (B, returnedSalt) = server.GeneratePublicKeyAndSalt();

            // Сохраняем данные в сессии
            HttpContext.Session.SetString(ServerBKey, B.ToString());
            HttpContext.Session.SetString(ServerSaltKey, returnedSalt.ToString());
            HttpContext.Session.SetString(ServerUsernameKey, request.Username);
            HttpContext.Session.SetString(ServerVerifierKey, verifier.ToString());
            HttpContext.Session.SetString(ServerPrivateBKey, typeof(SrpServer)
                .GetField("_b", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)
                .GetValue(server).ToString());

            // Вычисляем сеансовый ключ для всех случаев
            server.ComputeSessionKey(BigInteger.Parse(request.A));

            // Всегда возвращаем успешный ответ
            return Ok(new LoginResponse
            {
                B = B.ToString(),
                Salt = returnedSalt.ToString()
            });
        }

        [HttpPost("verify")]
        public IActionResult VerifyClient([FromBody] ClientProofRequest request)
        {
            var B = HttpContext.Session.GetString(ServerBKey);
            var salt = HttpContext.Session.GetString(ServerSaltKey);
            var username = HttpContext.Session.GetString(ServerUsernameKey);
            var verifier = HttpContext.Session.GetString(ServerVerifierKey);
            var privateB = HttpContext.Session.GetString(ServerPrivateBKey);

            if (string.IsNullOrEmpty(B) || string.IsNullOrEmpty(salt) || string.IsNullOrEmpty(username) ||
                string.IsNullOrEmpty(verifier) || string.IsNullOrEmpty(privateB))
            {
                return BadRequest(new { Message = "Session not started" });
            }

            var server = new SrpServer(username, BigInteger.Parse(salt), BigInteger.Parse(verifier));
            typeof(SrpServer).GetField("_B", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)
                .SetValue(server, BigInteger.Parse(B));
            typeof(SrpServer).GetField("_b", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)
                .SetValue(server, BigInteger.Parse(privateB));

            var A = BigInteger.Parse(request.M1.Split('|')[0]);
            var M1 = BigInteger.Parse(request.M1.Split('|')[1]);

            server.ComputeSessionKey(A);

            if (!server.VerifyClientProof(A, M1))
            {
                return BadRequest(new { Message = "Client proof verification failed" });
            }

            var M2 = server.ComputeServerProof(A, M1);
            return Ok(new ServerProofResponse { M2 = M2.ToString() });
        }
    }
}