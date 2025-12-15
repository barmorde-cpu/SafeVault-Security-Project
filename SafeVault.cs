using System;
using System.Data.SqlClient;
using System.Text.RegularExpressions;
using System.Web; // For HttpUtility
using BCrypt.Net; // Requires BCrypt.Net-Next package

namespace SafeVaultApp
{
    public class User
    {
        public int Id { get; set; }
        public string Username { get; set; }
        public string Email { get; set; }
        public string PasswordHash { get; set; }
        public string Role { get; set; } // "User" or "Admin"
    }

    public class SecurityService
    {
        private string _connectionString = "Server=myServer;Database=SafeVault;User Id=myUser;Password=myPassword;";

        // ACTIVITY 1 & 3: Input Validation & XSS Prevention
        public string SanitizeInput(string input)
        {
            if (string.IsNullOrEmpty(input)) return string.Empty;

            // 1. Remove dangerous characters (Allow only Alphanumeric and specific symbols)
            // Copilot suggested Regex to whitelist characters to prevent XSS at the source
            if (!Regex.IsMatch(input, @"^[a-zA-Z0-9@.]+$"))
            {
                throw new ArgumentException("Invalid characters detected.");
            }

            // 2. Encode output to prevent XSS (if this string is displayed in HTML)
            return HttpUtility.HtmlEncode(input);
        }

        // ACTIVITY 2: Authentication (Register with Hashing)
        public void RegisterUser(string username, string email, string password, string role)
        {
            string cleanUser = SanitizeInput(username);
            string cleanEmail = SanitizeInput(email);
            
            // Secure Password Hashing using BCrypt
            string passwordHash = BCrypt.Net.BCrypt.HashPassword(password);

            using (SqlConnection conn = new SqlConnection(_connectionString))
            {
                // ACTIVITY 1 & 3: SQL Injection Prevention (Parameterized Queries)
                string query = "INSERT INTO Users (Username, Email, PasswordHash, Role) VALUES (@user, @email, @pass, @role)";
                
                using (SqlCommand cmd = new SqlCommand(query, conn))
                {
                    cmd.Parameters.AddWithValue("@user", cleanUser);
                    cmd.Parameters.AddWithValue("@email", cleanEmail);
                    cmd.Parameters.AddWithValue("@pass", passwordHash);
                    cmd.Parameters.AddWithValue("@role", role);

                    conn.Open();
                    cmd.ExecuteNonQuery();
                }
            }
        }

        // ACTIVITY 2: Authentication (Login)
        public User Login(string username, string password)
        {
            string cleanUser = SanitizeInput(username);

            using (SqlConnection conn = new SqlConnection(_connectionString))
            {
                // Secure Query
                string query = "SELECT Id, Username, Email, PasswordHash, Role FROM Users WHERE Username = @user";
                
                using (SqlCommand cmd = new SqlCommand(query, conn))
                {
                    cmd.Parameters.AddWithValue("@user", cleanUser);
                    conn.Open();

                    using (SqlDataReader reader = cmd.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            string storedHash = reader["PasswordHash"].ToString();
                            
                            // Verify Password
                            if (BCrypt.Net.BCrypt.Verify(password, storedHash))
                            {
                                return new User
                                {
                                    Id = (int)reader["Id"],
                                    Username = reader["Username"].ToString(),
                                    Role = reader["Role"].ToString()
                                };
                            }
                        }
                    }
                }
            }
            return null; // Login failed
        }

        // ACTIVITY 2: Authorization (RBAC)
        public void AccessAdminDashboard(User currentUser)
        {
            if (currentUser == null)
            {
                throw new UnauthorizedAccessException("User is not logged in.");
            }

            if (currentUser.Role != "Admin")
            {
                throw new UnauthorizedAccessException("Access Denied: Requires Admin Role.");
            }

            Console.WriteLine("Welcome to the Admin Dashboard.");
        }
    }
}