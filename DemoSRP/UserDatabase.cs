using System;
using System.Numerics;
using Microsoft.Data.Sqlite;

namespace SRP
{
    public class UserDatabase
    {
        private readonly string _connectionString;

        public UserDatabase(string dbPath = "users.db")
        {
            _connectionString = $"Data Source={dbPath}";
            InitializeDatabase();
        }

        private void InitializeDatabase()
        {
            using (var connection = new SqliteConnection(_connectionString))
            {
                connection.Open();
                var command = connection.CreateCommand();
                command.CommandText = @"
                    CREATE TABLE IF NOT EXISTS Users (
                        Username TEXT PRIMARY KEY,
                        Salt TEXT NOT NULL,
                        Verifier TEXT NOT NULL
                    )";
                command.ExecuteNonQuery();
            }
        }

        public void RegisterUser(string username, BigInteger salt, BigInteger verifier)
        {
            using (var connection = new SqliteConnection(_connectionString))
            {
                connection.Open();
                var command = connection.CreateCommand();
                command.CommandText = @"
                    INSERT OR REPLACE INTO Users (Username, Salt, Verifier)
                    VALUES (@username, @salt, @verifier)";
                command.Parameters.AddWithValue("@username", username);
                command.Parameters.AddWithValue("@salt", salt.ToString());
                command.Parameters.AddWithValue("@verifier", verifier.ToString());
                command.ExecuteNonQuery();
            }
        }

        public (BigInteger Salt, BigInteger Verifier)? GetUserData(string username)
        {
            using (var connection = new SqliteConnection(_connectionString))
            {
                connection.Open();
                var command = connection.CreateCommand();
                command.CommandText = @"
                    SELECT Salt, Verifier
                    FROM Users
                    WHERE Username = @username";
                command.Parameters.AddWithValue("@username", username);

                using (var reader = command.ExecuteReader())
                {
                    if (reader.Read())
                    {
                        var salt = BigInteger.Parse(reader.GetString(0));
                        var verifier = BigInteger.Parse(reader.GetString(1));
                        return (salt, verifier);
                    }
                    return null;
                }
            }
        }
    }
}