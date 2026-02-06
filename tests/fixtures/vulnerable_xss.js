// INTENTIONALLY VULNERABLE CODE - FOR TESTING ONLY
// Cross-Site Scripting (XSS) vulnerabilities in JavaScript

// VULNERABLE: innerHTML with user input
function displayUsername(username) {
    document.getElementById('user').innerHTML = username;
}

// VULNERABLE: document.write with user data
function showMessage(message) {
    document.write("<div>" + message + "</div>");
}

// VULNERABLE: eval with user input
function executeCode(userCode) {
    eval(userCode);
}

// VULNERABLE: Unsafe React dangerouslySetInnerHTML
function UserComment({ comment }) {
    return (
        <div dangerouslySetInnerHTML={{ __html: comment }} />
    );
}

// VULNERABLE: jQuery manipulation
function updateContent(html) {
    $('#content').html(html);
}

// VULNERABLE: SQL injection in Node.js
function getUserData(userId) {
    const query = "SELECT * FROM users WHERE id = " + userId;
    db.query(query, (err, results) => {
        return results;
    });
}

// VULNERABLE: Command injection
function execCommand(filename) {
    const { exec } = require('child_process');
    exec('ls -la ' + filename, (error, stdout) => {
        console.log(stdout);
    });
}

// VULNERABLE: Hardcoded secrets
const API_KEY = "sk_test_abcdefgh12345678";
const SECRET_TOKEN = "ghp_1234567890abcdefghijklmnop";

// VULNERABLE: Prototype pollution
function merge(target, source) {
    for (let key in source) {
        target[key] = source[key];  // Can pollute __proto__
    }
    return target;
}

// SAFE EXAMPLES
function safeDisplayUsername(username) {
    // SAFE: textContent doesn't parse HTML
    document.getElementById('user').textContent = username;
}

function safeGetUserData(userId) {
    // SAFE: Parameterized query
    const query = "SELECT * FROM users WHERE id = ?";
    db.query(query, [userId], (err, results) => {
        return results;
    });
}
