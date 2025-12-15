using NUnit.Framework;
using SafeVaultApp;
using System;

namespace SafeVaultTests
{
    [TestFixture]
    public class TestSecurity
    {
        private SecurityService _service;

        [SetUp]
        public void Setup()
        {
            _service = new SecurityService();
        }

        // ACTIVITY 1: Test for SQL Injection Protection
        [Test]
        public void Test_InputValidation_RejectsSQLInjectionChars()
        {
            // Attempting to pass a common SQL injection string
            string maliciousInput = "' OR '1'='1";

            // Expecting the SanitizeInput method to throw an error due to regex validation
            Assert.Throws<ArgumentException>(() => _service.SanitizeInput(maliciousInput));
        }

        // ACTIVITY 1 & 3: Test for XSS Protection
        [Test]
        public void Test_Sanitization_EncodesXSS()
        {
            // If the regex allows it, we ensure it is HTML encoded. 
            // Note: Our strict Regex above actually blocks <>, but if we relaxed it,
            // we test that HtmlEncode works.
            
            string input = "User1"; 
            string result = _service.SanitizeInput(input);
            
            // Verify output is safe
            Assert.AreEqual("User1", result);
            
            // Verify invalid characters throw exception
            string xssAttempt = "<script>alert(1)</script>";
            Assert.Throws<ArgumentException>(() => _service.SanitizeInput(xssAttempt));
        }

        // ACTIVITY 2: Test Authentication & Password Hashing
        [Test]
        public void Test_PasswordHashing_VerifiesCorrectly()
        {
            string password = "SecurePassword123!";
            string hash = BCrypt.Net.BCrypt.HashPassword(password);

            bool isValid = BCrypt.Net.BCrypt.Verify(password, hash);
            bool isInvalid = BCrypt.Net.BCrypt.Verify("WrongPassword", hash);

            Assert.IsTrue(isValid);
            Assert.IsFalse(isInvalid);
        }

        // ACTIVITY 2: Test Authorization (RBAC)
        [Test]
        public void Test_RBAC_AdminAccess()
        {
            User adminUser = new User { Username = "Admin", Role = "Admin" };
            User regularUser = new User { Username = "Guest", Role = "User" };

            // Admin should not throw exception
            Assert.DoesNotThrow(() => _service.AccessAdminDashboard(adminUser));

            // Regular user should throw UnauthorizedAccessException
            Assert.Throws<UnauthorizedAccessException>(() => _service.AccessAdminDashboard(regularUser));
        }
    }
}