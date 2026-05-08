import { useState } from "react";

import BlindSSRF from "./assets/Blind Server-Side Request Forgery (SSRF).jpg";
import BrokenAuth from "./assets/Broken Authentication (Missing JWT Validation).jpg";
import ExcessiveData from "./assets/Excessive Data Exposure (ID: 15).jpg";
import Fingerprinting from "./assets/Fingerprinting & Server Information Disclosure (ID: 20).jpg";
import InsecureStorage from "./assets/Insecure Client-Side Storage (Local Storage Leak).jpg";
import MissingHeaders from "./assets/Missing Security Headers (ID: 10).jpg";
import PathTraversal from "./assets/Path Traversal (ID: 13).jpg";
import PrivilegeEscalation from "./assets/Privilege Escalation via Client-Side Manipulation.jpg";
import SQLInjection from "./assets/SQL Injection (Authentication Bypass).jpg";
import SensitiveDisclosure from "./assets/Sensitive Infrastructure Information Disclosure.jpg";
import VerboseErrors from "./assets/Verbose Error Messages & Internal Information Disclosure.jpg";
import broken_auth from "./assets/broken_auth.jpg";

interface Vuln {
  id: number;
  title: string;
  severity: "Critical" | "High" | "Medium" | "Low";
  cwe: string;
  owasp: string;
  endpoint: string;
  desc: string;
  evidence: string;
  imgKey: string;
  imgLabel: string;
  imgKey2?: string;
  imgLabel2?: string;
  before: string;
  after: string;
  changed: string;
}

const vulns: Vuln[] = [
  {
    id: 1,
    title: "SQL Injection (Authentication Bypass)",
    severity: "Critical",
    cwe: "CWE-89",
    owasp: "A03:2021 – Injection",
    endpoint: "https://darrag.online/auth/signin",
    desc: "The login form relies on client-side validation (type=\"email\"). By using browser DevTools to change the input type to \"text\", an attacker can inject SQL payloads. The backend fails to sanitize input, allowing complete authentication bypass.",
    evidence: "Payload: admin' OR '1'='1\\nResult: Successful login without valid password. Input type changed via Inspect Element.",
    imgKey: "SQLInjection",
    imgLabel: "SQL Injection — DevTools showing payload injected in email field",
    before: `// UserService.cs
public async Task<User> LoginAsync(string email, string password)
{
    var hashedPassword = HashPassword(password);
    // ❌ Direct interpolation — SQL Injection!
    return await _context.Users
        .FromSqlRaw($"SELECT * FROM Users WHERE Email = '{email}'
                    AND Password = '{hashedPassword}'")
        .FirstOrDefaultAsync();
}`,
    after: `// UserService.cs
public async Task<User> LoginAsync(string email, string password)
{
    // ✅ Parameterized LINQ query
    var user = await _context.Users
        .FirstOrDefaultAsync(u => u.Email == email);
    if (user == null || !VerifyPassword(password, user.Password))
        return null;
    return user;
}`,
    changed: "Replaced vulnerable FromSqlRaw with parameterized LINQ query. Added server-side password verification."
  },
  {
    id: 2,
    title: "Blind SSRF via API Endpoint Configuration",
    severity: "Critical",
    cwe: "CWE-918",
    owasp: "A10:2021 – Server-Side Request Forgery",
    endpoint: "darrag.online/settings → API Config",
    desc: "The Base URL field accepts any URI without validation. The server makes unmonitored outbound requests and returns 'Connected' regardless of validity. Enables internal port scanning and access to cloud metadata services.",
    evidence: "Payload: http://192.168.1.10:8080 (internal IP)\\nResponse: 'Connected ✓' status returned, confirming the server made an outbound request to an internal address.",
    imgKey: "BlindSSRF",
    imgLabel: "SSRF — 'Connected' status returned for an internal IP address, indicating a successful SSRF.",
    before: `// AdminController.cs
[HttpPost("run-scan")]
public async Task<IActionResult> RunScan([FromBody] ScanRequest request)
{
    // ❌ No URL validation — any URI accepted
    var response = await _httpClient.GetAsync(request.BaseUrl);
    var content = await response.Content.ReadAsStringAsync();
    return Ok(new { message = "Scan completed", data = content });
}`,
    after: `// AdminController.cs
[HttpPost("run-scan")]
public async Task<IActionResult> RunScan([FromBody] ScanRequest request)
{
    if (!Uri.TryCreate(request.BaseUrl, UriKind.Absolute, out var uri) ||
        (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        return BadRequest("Invalid URL scheme.");

    // ✅ Allowlist check
    var allowedHosts = new[] { "localhost", "codescan.io" };
    if (!allowedHosts.Contains(uri.Host))
        return BadRequest("URL not from an allowed domain.");

    var response = await _httpClient.GetAsync(uri);
    return Ok(new { message = "Scan completed" });
}`,
    changed: "Added URI scheme validation and allowlist for trusted domains to prevent SSRF."
  },
  {
    id: 3,
    title: "Directory Traversal & Internal Path Disclosure",
    severity: "High",
    cwe: "CWE-22",
    owasp: "A01:2021 – Broken Access Control",
    endpoint: "https://darrag.online/api/VulnEndpoints/download?file=",
    desc: "The download endpoint accepts a 'file' parameter without sanitization. The error response leaked the absolute server path, revealing the application's directory structure on the Linux server.",
    evidence: "Payload: ?file=../../../../etc/passwd\\nLeaked: The error message revealed the full internal path /var/www/project_vulner/publish/backend/ and confirmed the traversal attempt.",
    imgKey: "PathTraversal",
    imgLabel: "Path Traversal — Server leaks internal path /var/www/project_vulner/ in error response",
    before: `// VulnEndpointsController.cs
[HttpGet("download")]
public IActionResult DownloadFile(string file)
{
    // ❌ Direct concatenation — traversal possible
    var filePath = Path.Combine("/var/www/uploads", file);
    if (!System.IO.File.Exists(filePath))
        // ❌ Leaks internal path in error
        return NotFound(new { error = "File not found", path = filePath });
}`,
    after: `// VulnEndpointsController.cs
[HttpGet("download")]
public IActionResult DownloadFile(string file)
{
    var safeFileName = Path.GetFileName(file);
    if (string.IsNullOrEmpty(safeFileName))
        return BadRequest("Invalid file name.");

    var basePath = "/var/www/uploads";
    var filePath = Path.Combine(basePath, safeFileName);

    // ✅ Boundary check
    if (!Path.GetFullPath(filePath).StartsWith(Path.GetFullPath(basePath)))
        return StatusCode(403, "Path traversal detected.");

    if (!System.IO.File.Exists(filePath))
        return NotFound(); // ✅ No path info in error
}`,
    changed: "Sanitized filename with Path.GetFileName(), added full path boundary check, removed path from error response."
  },
  {
    id: 4,
    title: "Missing Security Headers",
    severity: "Medium",
    cwe: "CWE-1021",
    owasp: "A05:2021 – Security Misconfiguration",
    endpoint: "All HTTP responses",
    desc: "HTTP responses lack essential security headers. Absence of CSP, X-Frame-Options, and X-Content-Type-Options exposes users to Clickjacking and XSS attacks.",
    evidence: "Verified via Network tab → Response Headers:\\n• No X-Frame-Options\\n• No Content-Security-Policy\\n• No X-Content-Type-Options",
    imgKey: "MissingHeaders",
    imgLabel: "Missing Headers — Browser DevTools showing lack of security headers in the response",
    before: `// Program.cs
app.UseHttpsRedirection();
// ❌ No security headers middleware
app.MapControllers();
app.Run();`,
    after: `// Program.cs
// ✅ Security headers middleware
app.Use(async (context, next) => {
    context.Response.Headers.Append("X-Content-Type-Options", "nosniff");
    context.Response.Headers.Append("X-Frame-Options", "DENY");
    context.Response.Headers.Append("Content-Security-Policy",
        "default-src 'self'; script-src 'self'; object-src 'none';");
    context.Response.Headers.Append("Strict-Transport-Security",
        "max-age=31536000; includeSubDomains");
    await next();
});
app.UseHttpsRedirection();
app.MapControllers();`,
    changed: "Added middleware injecting CSP, X-Frame-Options, X-Content-Type-Options, and HSTS to all responses."
  },
  {
    id: 5,
    title: "Excessive Data Exposure via API",
    severity: "High",
    cwe: "CWE-213",
    owasp: "A01:2021 – Broken Access Control",
    endpoint: "https://darrag.online/api/codescans",
    desc: "The /api/codescans endpoint returns complete database objects including internal IDs, full scan metadata, and user-related fields. Visible in Network tab — attacker can gather intelligence on other users' scans.",
    evidence: "The API response for /api/codescans includes sensitive data for all users, not just the authenticated user. The screenshot shows the raw JSON response containing objects with 'id', 'projectName', 'status', 'scanDate', and 'user' fields.",
    imgKey: "ExcessiveData",
    imgLabel: "Excessive Data Exposure — Raw API response from /api/codescans leaking other users' data",
    before: `// CodeScansController.cs
[HttpGet]
public async Task<ActionResult<IEnumerable<CodeScan>>> GetScans()
{
    // ❌ Returns full entity with all sensitive fields
    return await _context.CodeScans.ToListAsync();
}`,
    after: `// CodeScansController.cs
[HttpGet]
public async Task<ActionResult<IEnumerable<CodeScanDto>>> GetScans()
{
    // ✅ Return only non-sensitive fields via DTO
    return await _context.CodeScans
        .Select(scan => new CodeScanDto {
            Id = scan.Id,
            ProjectName = scan.ProjectName,
            Status = scan.Status,
            ScanDate = scan.ScanDate
        }).ToListAsync();
}`,
    changed: "Introduced CodeScanDto to return only necessary non-sensitive fields to the client."
  },
  {
    id: 6,
    title: "Verbose Error Messages & Path Disclosure",
    severity: "Medium",
    cwe: "CWE-209",
    owasp: "A05:2021 – Security Misconfiguration",
    endpoint: "All error responses",
    desc: "The application exposes detailed internal error messages in production, including absolute file paths and internal server structure that aid attacker reconnaissance.",
    evidence: "Error response exposed: /var/www/project_vulner/publish/backend/ confirming Linux server path.",
    imgKey: "VerboseErrors",
    imgLabel: "Verbose Errors — Path Traversal response leaking internal server path",
    before: `// Program.cs
// ❌ Developer exception page active in ALL environments
app.UseDeveloperExceptionPage();
app.UseHttpsRedirection();`,
    after: `// Program.cs
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage(); // ✅ Dev only
}
else
{
    app.UseExceptionHandler("/Error"); // ✅ Generic in production
    app.UseHsts();
}
app.UseHttpsRedirection();`,
    changed: "Restricted developer exception page to development environment only."
  },
  {
    id: 7,
    title: "Infrastructure Fingerprinting",
    severity: "Low",
    cwe: "CWE-200",
    owasp: "A05:2021 – Security Misconfiguration",
    endpoint: "All HTTP response headers",
    desc: "Response headers reveal Cloudflare as proxy/WAF, specific compression algorithms (zstd), and Cf-Ray identifiers. Simplifies attacker reconnaissance phase.",
    evidence: "Headers found:\\n• Server: cloudflare\\n• Content-Encoding: zstd\\n• Cf-Ray: 9f82d9207a5be1bc-MRS",
    imgKey: "Fingerprinting",
    imgLabel: "Fingerprinting — Response headers revealing Server: cloudflare, Content-Encoding: zstd",
    before: `// Default ASP.NET Core / Kestrel
// ❌ Server header included by default`,
    after: `// Program.cs
// ✅ Suppress Server header
builder.WebHost.ConfigureKestrel(serverOptions => {
    serverOptions.AddServerHeader = false;
});
var app = builder.Build();`,
    changed: "Configured Kestrel to suppress the Server header, reducing fingerprinting surface."
  },
  {
    id: 8,
    title: "Broken Authentication & Admin Data Leak",
    severity: "Critical",
    cwe: "CWE-306",
    owasp: "A07:2021 – Identification and Authentication Failures",
    endpoint: "https://darrag.online/api/admin/users",
    desc: "The /api/admin/users endpoint is publicly accessible without any authentication. A direct GET request with no Authorization header returns a complete user list including IDs, emails, roles, and subscription plans.",
    evidence: "No Authorization header sent → HTTP 200 OK returned.\\nData leaked: admin@codescan.io (Admin/Premium), user@codescan.io (User/Trial), dev@codescan.io (User/Pro)",
    imgKey: "BrokenAuth",
    imgLabel: "Broken Auth — GET /api/admin/users returns 200 OK without any Authorization header",
    imgKey2: "broken_auth",
    imgLabel2: "Admin Data Leak — Full user list with roles and plans returned unauthenticated",
    before: `// AdminController.cs
[ApiController]
[Route("api/[controller]")]
// ❌ No [Authorize] — anyone can access
public class AdminController : ControllerBase
{
    [HttpGet("users")]
    public async Task<ActionResult<IEnumerable<User>>> GetUsers()
    {
        return await _userService.GetAllUsersAsync();
    }
}`,
    after: `// AdminController.cs
[ApiController]
[Route("api/[controller]")]
[Authorize(Roles = "Admin")] // ✅ Controller-level auth
public class AdminController : ControllerBase
{
    [HttpGet("users")]
    public async Task<ActionResult<IEnumerable<UserSummaryDto>>> GetUsers()
    {
        var users = await _userService.GetAllUsersAsync();
        var summaries = users.Select(u => new UserSummaryDto {
            Id = u.Id, Email = u.Email, Name = u.Name
        });
        return Ok(summaries);
    }
}`,
    changed: "Applied [Authorize(Roles=\"Admin\")] to entire AdminController. Returns DTO instead of full user objects."
  },
  {
    id: 9,
    title: "Critical Config & JWT Secret Exposure",
    severity: "Critical",
    cwe: "CWE-200",
    owasp: "A05:2021 – Security Misconfiguration",
    endpoint: "https://darrag.online/api/admin/config",
    desc: "The /api/admin/config endpoint is publicly accessible and exposes critical production secrets. With the JWT secret key, an attacker can forge admin tokens to permanently impersonate any user.",
    evidence: "Exposed: dbConnectionString: Data Source=ProjectVuln.db\\njwtSecret: dev-secret-key-change ← Allows forging ANY JWT token\\naiServiceUrl: http://ai:8000 ← Internal service exposed",
    imgKey: "SensitiveDisclosure",
    imgLabel: "Config Exposure — jwtSecret and dbConnectionString exposed at /api/admin/config",
    before: `// AdminController.cs
[HttpGet("config")]
public IActionResult GetConfig()
{
    // ❌ Returns ALL config including secrets
    return Ok(_configuration.AsEnumerable());
}`,
    after: `// AdminController.cs
[HttpGet("config")]
// ✅ Requires Admin role (from controller [Authorize])
public IActionResult GetConfig()
{
    // ✅ Only non-sensitive values returned
    var safeConfig = new {
        AppVersion = _configuration["AppVersion"],
        Environment = _configuration["Environment"]
    };
    return Ok(safeConfig);
}`,
    changed: "Removed all secrets from response. Endpoint now requires Admin auth and returns only safe config values."
  },
  {
    id: 10,
    title: "Privilege Escalation via Client-Side Manipulation",
    severity: "High",
    cwe: "CWE-639",
    owasp: "A07:2021 – Identification and Authentication Failures",
    endpoint: "Browser DevTools → Application → Local Storage",
    desc: "The application trusts the role value stored in Local Storage to render UI components. A user can manually modify role: 'user' to role: 'admin' in DevTools to gain unauthorized access to admin UI features.",
    evidence: "codescan_auth localStorage value modified:\\nBefore: role: \"user\"\\nAfter: role: \"admin\" → Admin UI components revealed",
    imgKey: "PrivilegeEscalation",
    imgLabel: "Privilege Escalation — role changed from 'user' to 'admin' via DevTools localStorage edit",
    before: `// ❌ Client trusts localStorage role for UI rendering
const role = JSON.parse(localStorage.getItem('codescan_auth')).user.role;
if (role === 'admin') {
    showAdminPanel(); // Shown based on client-side value only
}`,
    after: `// ✅ Server enforces role — client value irrelevant
[HttpPost("critical-action")]
[Authorize(Roles = "Admin")] // Role validated from JWT
public IActionResult PerformCriticalAction()
{
    // Unreachable without valid Admin JWT claim
    return Ok("Action performed by authorized admin.");
}`,
    changed: "Server enforces role-based authorization from validated JWT. localStorage manipulation has no security effect."
  },
  {
    id: 11,
    title: "Insecure Client-Side Storage",
    severity: "Medium",
    cwe: "CWE-312",
    owasp: "A02:2021 – Cryptographic Failures",
    endpoint: "Browser → Application → Local Storage → codescan_auth",
    desc: "Sensitive user identity information including email addresses, system roles, and authentication tokens are stored in plain text in browser localStorage. Token value is a hardcoded 'mock-token' — insecure placeholder in production.",
    evidence: "codescan_auth key stores: {user: {id, email: 'demo@codescan.com', role: 'user'}, token: 'mock-token'}\\nAll data visible in plain text to any JavaScript on the page.",
    imgKey: "InsecureStorage",
    imgLabel: "Insecure Storage — codescan_auth key with plaintext user data in localStorage",
    before: `// ❌ Sensitive data in localStorage — XSS accessible
localStorage.setItem('codescan_auth', JSON.stringify({
    user: { id: 'xt4h2js7v', email: 'demo@codescan.com',
            name: 'demo', role: 'user' },
    token: 'mock-token'  // ❌ Hardcoded mock token
}));`,
    after: `// ✅ Use httpOnly cookies for auth tokens
// Set by server — inaccessible to JavaScript
Response.Cookies.Append("auth_token", jwtToken, new CookieOptions {
    HttpOnly = true,   // ✅ No JS access
    Secure = true,     // ✅ HTTPS only
    SameSite = SameSiteMode.Strict,
    Expires = DateTimeOffset.UtcNow.AddHours(1)
});
// Store only non-sensitive UI preferences in localStorage`,
    changed: "Auth tokens moved to httpOnly cookies. Sensitive user data removed from localStorage."
  }
];

const images: Record<string, string> = {
  BlindSSRF,
  BrokenAuth,
  ExcessiveData,
  Fingerprinting,
  InsecureStorage,
  MissingHeaders,
  PathTraversal,
  PrivilegeEscalation,
  SQLInjection,
  SensitiveDisclosure,
  VerboseErrors,
  broken_auth,
};

const severityColor: Record<
  string,
  {
    bg: string;
    border: string;
    text: string;
    badge: string;
  }
> = {
  Critical: {
    bg: "#fff0f0",
    border: "#cc0000",
    text: "#cc0000",
    badge: "#cc0000",
  },
  High: {
    bg: "#fff5e6",
    border: "#e06c00",
    text: "#e06c00",
    badge: "#e06c00",
  },
  Medium: {
    bg: "#fffbe6",
    border: "#c9a800",
    text: "#b8860b",
    badge: "#c9a800",
  },
  Low: {
    bg: "#f0fff0",
    border: "#2e7d32",
    text: "#2e7d32",
    badge: "#2e7d32",
  },
};

const counts = {
  Critical: 0,
  High: 0,
  Medium: 0,
  Low: 0,
};

vulns.forEach((v) => {
  counts[v.severity] = (counts[v.severity] || 0) + 1;
});

export default function App() {
  const [activeVuln, setActiveVuln] = useState<number | null>(null);

  const [lightboxImage, setLightboxImage] = useState<string | null>(null);

  return (
    <div
      style={{
        fontFamily: "Arial, sans-serif",
        background: "#f4f6fb",
        minHeight: "100vh",
        padding: "0 0 40px 0",
      }}
    >
      {/* LIGHTBOX */}
      {lightboxImage && (
        <div
          onClick={() => setLightboxImage(null)}
          style={{
            position: "fixed",
            inset: 0,
            background: "rgba(0,0,0,0.85)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 9999,
            padding: 20,
            cursor: "pointer",
          }}
        >
          <img
            src={lightboxImage}
            alt="Evidence"
            style={{
              maxWidth: "95%",
              maxHeight: "95%",
              borderRadius: 10,
              boxShadow: "0 0 30px rgba(0,0,0,0.5)",
            }}
          />
        </div>
      )}

      {/* HEADER */}
      <div
        style={{
          background:
            "linear-gradient(135deg, #1a2c6b 0%, #2e4a9e 100%)",
          color: "#fff",
          padding: "36px 40px 28px",
        }}
      >
        <div
          style={{
            fontSize: 11,
            letterSpacing: 3,
            color: "#aac4ff",
            marginBottom: 8,
          }}
        >
          CONFIDENTIAL — SECURITY ASSESSMENT
        </div>

        <div
          style={{
            fontSize: 28,
            fontWeight: 900,
            letterSpacing: 1,
          }}
        >
          Penetration Test Report
        </div>

        <div
          style={{
            fontSize: 15,
            color: "#c5d5ff",
            marginTop: 6,
          }}
        >
          Target: <b style={{ color: "#fff" }}>darrag.online</b>
          &nbsp;|&nbsp; Date: May 8, 2026
        </div>

        <div
          style={{
            display: "flex",
            gap: 16,
            marginTop: 24,
          }}
        >
          {Object.entries(counts).map(([sev, cnt]) => (
            <div
              key={sev}
              style={{
                background: "rgba(255,255,255,0.1)",
                borderRadius: 10,
                padding: "10px 20px",
                textAlign: "center",
                border: `2px solid ${
                  severityColor[sev as keyof typeof severityColor]?.badge || "#fff"
                }`,
              }}
            >
              <div
                style={{
                  fontSize: 26,
                  fontWeight: 900,
                  color: severityColor[sev as keyof typeof severityColor]?.badge || "#fff",
                }}
              >
                {cnt}
              </div>

              <div
                style={{
                  fontSize: 11,
                  color: "#ddeeff",
                  letterSpacing: 1,
                }}
              >
                {sev.toUpperCase()}
              </div>
            </div>
          ))}

          <div
            style={{
              background: "rgba(255,255,255,0.1)",
              borderRadius: 10,
              padding: "10px 20px",
              textAlign: "center",
              border: "2px solid #ffffff44",
            }}
          >
            <div
              style={{
                fontSize: 26,
                fontWeight: 900,
              }}
            >
              {vulns.length}
            </div>

            <div
              style={{
                fontSize: 11,
                color: "#ddeeff",
                letterSpacing: 1,
              }}
            >
              TOTAL
            </div>
          </div>
        </div>
      </div>

      {/* VULNS */}
      <div style={{ padding: "28px 32px 0" }}>
        {vulns.map((v) => {
          const sc = severityColor[v.severity];
          const open = activeVuln === v.id;

          return (
            <div
              key={v.id}
              style={{
                marginBottom: 16,
                borderRadius: 10,
                border: `1.5px solid ${sc.border}`,
                background: "#fff",
                overflow: "hidden",
                boxShadow: "0 2px 8px #0001",
              }}
            >
              {/* HEADER ROW */}
              <div
                onClick={() =>
                  setActiveVuln(open ? null : v.id)
                }
                style={{
                  display: "flex",
                  alignItems: "center",
                  padding: "14px 20px",
                  cursor: "pointer",
                  background: open ? sc.bg : "#fff",
                  gap: 14,
                }}
              >
                <div
                  style={{
                    width: 32,
                    height: 32,
                    borderRadius: "50%",
                    background: sc.badge,
                    color: "#fff",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    fontWeight: 900,
                    fontSize: 13,
                    flexShrink: 0,
                  }}
                >
                  {v.id}
                </div>

                <div style={{ flex: 1 }}>
                  <div
                    style={{
                      fontWeight: 700,
                      fontSize: 15,
                      color: "#1a2c6b",
                    }}
                  >
                    {v.title}
                  </div>

                  <div
                    style={{
                      fontSize: 12,
                      color: "#666",
                      marginTop: 2,
                    }}
                  >
                    {v.cwe} | {v.owasp}
                  </div>
                </div>

                <span
                  style={{
                    background: sc.badge,
                    color: "#fff",
                    borderRadius: 6,
                    padding: "3px 12px",
                    fontSize: 12,
                    fontWeight: 700,
                  }}
                >
                  {v.severity}
                </span>
              </div>

              {/* CONTENT */}
              {open && (
                <div
                  style={{
                    borderTop: `1.5px solid ${sc.border}`,
                    padding: 24,
                  }}
                >
                  <p>{v.desc}</p>

                  <pre
                    style={{
                      background: "#1a1a2e",
                      color: "#00ff88",
                      borderRadius: 8,
                      padding: 14,
                      whiteSpace: "pre-wrap",
                    }}
                  >
                    {v.evidence}
                  </pre>

                  <div
                    style={{
                      marginTop: 16,
                      cursor: "pointer",
                    }}
                    onClick={() =>
                      setLightboxImage(images[v.imgKey])
                    }
                  >
                    <img
                      src={images[v.imgKey]}
                      alt={v.imgLabel}
                      style={{
                        width: "100%",
                        maxWidth: 500,
                        borderRadius: 8,
                        border: "1px solid #ddd",
                      }}
                    />
                  </div>

                  <div style={{ marginTop: 24 }}>
                    <div
                      style={{
                        background: "#fff5f5",
                        border: "1px solid #cc0000",
                        borderRadius: 8,
                        marginBottom: 16,
                      }}
                    >
                      <div
                        style={{
                          background: "#cc0000",
                          color: "#fff",
                          padding: 10,
                          fontWeight: 700,
                        }}
                      >
                        ❌ BEFORE
                      </div>

                      <pre
                        style={{
                          padding: 16,
                          margin: 0,
                          overflowX: "auto",
                        }}
                      >
                        {v.before}
                      </pre>
                    </div>

                    <div
                      style={{
                        background: "#f0fff4",
                        border: "1px solid #2e7d32",
                        borderRadius: 8,
                      }}
                    >
                      <div
                        style={{
                          background: "#2e7d32",
                          color: "#fff",
                          padding: 10,
                          fontWeight: 700,
                        }}
                      >
                        ✅ AFTER
                      </div>

                      <pre
                        style={{
                          padding: 16,
                          margin: 0,
                          overflowX: "auto",
                        }}
                      >
                        {v.after}
                      </pre>
                    </div>

                    <div
                      style={{
                        marginTop: 12,
                        background: "#eaf4fb",
                        padding: 12,
                        borderRadius: 8,
                      }}
                    >
                      <b>What changed:</b> {v.changed}
                    </div>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* FOOTER */}
      <div
        style={{
          textAlign: "center",
          color: "#aaa",
          fontSize: 12,
          marginTop: 24,
        }}
      >
        End of Report — darrag.online Security Assessment — May 8, 2026
      </div>
    </div>
  );
}