# SafeVault Application Security Project

## Project Overview
SafeVault is a secure web application designed to manage sensitive user data. This project demonstrates the implementation of secure coding practices, authentication, authorization, and vulnerability remediation.

## Vulnerabilities Identified & Fixed

### 1. SQL Injection (SQLi)
*   **Vulnerability:** The initial codebase used string concatenation to build SQL queries (e.g., `"SELECT * FROM Users WHERE Username = '" + input + "'"`). This allowed attackers to manipulate queries.
*   **Fix:** Implemented **Parameterized Queries** using `SqlCommand` and `@parameters`. This ensures the database treats user input as data, not executable code.
*   **Copilot Assistance:** Copilot generated the syntax for `SqlParameter` and refactored raw strings into secure parameterized statements.

### 2. Cross-Site Scripting (XSS)
*   **Vulnerability:** User inputs (like usernames) were being displayed directly back to the browser without sanitization, allowing `<script>` tags to execute.
*   **Fix:** Implemented **Input Validation** (Regex) and **Output Encoding** (`HttpUtility.HtmlEncode`).
*   **Copilot Assistance:** Copilot provided Regex patterns to whitelist allowed characters and suggested the HtmlEncode method to neutralize script tags.

### 3. Weak Authentication
*   **Vulnerability:** Storing passwords in plain text or using weak hashing.
*   **Fix:** Implemented **BCrypt** for strong password hashing and salt generation. Added Role-Based Access Control (RBAC) to restrict Admin features.
*   **Copilot Assistance:** Copilot generated the logic for the `Login` method and the `[Authorize(Role = "Admin")]` pattern.

## Technologies Used
*   C# / .NET Core
*   NUnit (Testing)
*   BCrypt.Net (Security)