// Function to check for malicious code
function detectMaliciousCode(input) {
    // 1. Detecting SQL Injection patterns (basic examples)
    // Updated to check only for SQL keywords preceded or followed by common SQL injection indicators like quotes or comments
    const sqlInjectionPattern = /(\b(SELECT|INSERT|DELETE|UPDATE|DROP|UNION|CREATE|ALTER|EXEC)\b.*(--|'|;))/i;

    // 2. Detecting XSS Attack patterns (improved pattern)
    // Now checks for "<script" or event attributes without flagging safe inputs like email addresses
    const xssPattern = /(<script.*?>.*<\/script>|<.*on\w+=['"].*['"]|javascript:|<img.*src=.*>|<iframe.*>|<svg.*onload=.*>)/i;

    // 3. Detecting CSRF token absence pattern (simplified check)
    // This detection is very limited and better handled server-side
    const csrfPattern = /csrf_token\s*=\s*['"]?[a-zA-Z0-9]+['"]?/i;

    // Check for SQL Injection
    if (sqlInjectionPattern.test(input)) {
        console.log("Potential SQL Injection detected");
        return true;
    }

    // Check for XSS Attack
    if (xssPattern.test(input)) {
        console.log("Potential XSS Attack detected");
        return true;
    }

    // Check for missing CSRF token pattern (only if expecting CSRF token in inputs)
    // If you are not using CSRF tokens in the input fields, remove this check
    if (input.includes("csrf_token=") && !csrfPattern.test(input)) {
        console.log("Potential CSRF Attack detected (missing or invalid CSRF token)");
        return true;
    }

    // No malicious input detected
    return false;
}

// Handle Sign In form submission
function handleSignIn() {
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value.trim();

    // Validate for empty inputs first
    if (!username || !password) {
        alert("Username and password cannot be empty");
        return false;
    }

    if (detectMaliciousCode(username) || detectMaliciousCode(password)) {
        window.location.href = 'forbidden.html';
        return false;
    }

    window.location.href = 'login.html';
    return false;
}

// Handle Login form submission
function handleLogin() {
    const loginUsername = document.getElementById('loginUsername').value.trim();
    const loginPassword = document.getElementById('loginPassword').value.trim();

    // Validate for empty inputs first
    if (!loginUsername || !loginPassword) {
        alert("Username and password cannot be empty");
        return false;
    }

    if (detectMaliciousCode(loginUsername) || detectMaliciousCode(loginPassword)) {
        window.location.href = 'forbidden.html';
        return false;
    }

    window.location.href = 'home.html';
    return false;
}
