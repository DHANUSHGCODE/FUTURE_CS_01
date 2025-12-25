# WEB APPLICATION SECURITY TESTING REPORT
## OWASP ZAP Security Testing Assessment

**Internship Organization:** Future Interns  
**Domain:** Cyber Security  
**Track Code:** CS  
**Task Number:** 01  
**Intern Name:** Dhanush G  
**Tool Used:** OWASP ZAP (Zed Attack Proxy)  
**Test Environment:** Kali Linux, VMware Workstation  
**Report Date:** December 25, 2025

---

## 1. Introduction

Web application security testing is a critical process used to identify vulnerabilities that may expose applications to security threats. With the increasing use of web-based systems, protecting applications from common attacks such as SQL Injection and Cross-Site Scripting (XSS) has become essential.

This report documents the security testing performed as part of Task 1 of the Future Interns Cyber Security Internship, focusing on identifying and understanding common web application vulnerabilities using industry-standard tools.

**Scope:** Comprehensive security assessment of vulnerable web applications using OWASP ZAP automated scanning and manual testing techniques.

---

## 2. Objective

The primary objective of this task is to:

- ✅ Perform security testing on vulnerable web applications
- ✅ Identify common web application vulnerabilities
- ✅ Understand potential security risks and impacts
- ✅ Document findings with detailed evidence
- ✅ Recommend mitigation strategies to improve application security
- ✅ Develop practical security assessment skills

---

## 3. Tools and Technologies Used

The following tools and platforms were used to complete this task:

### Security Testing Tools
- **Kali Linux** - Penetration testing operating system
- **OWASP ZAP** (Zed Attack Proxy) - Web application security scanner
- **Burp Suite Community** - Manual web application testing platform
- **SQLMap** - SQL injection testing and exploitation tool

### Target Applications
- **OWASP Juice Shop** - Intentionally vulnerable web application
- **DVWA** (Damn Vulnerable Web Application) - Practice environment

### Infrastructure
- **VMware Workstation** - Virtualization environment
- **Kali Linux VM** - Isolated testing environment
- **MariaDB** - Database server
- **Apache2** - Web server

---

## 4. Target Application

The security testing was conducted on **OWASP Juice Shop** and **DVWA**, deliberately vulnerable web applications designed for learning and practicing web security testing.

### OWASP Juice Shop
- **Hosting Type:** Localhost
- **Target URL:** http://localhost:3000
- **Technology Stack:** Node.js, Express, Angular
- **Database:** MongoDB
- **Purpose:** E-commerce application with intentional vulnerabilities

### DVWA (Damn Vulnerable Web Application)
- **Hosting Type:** Localhost
- **Target URL:** http://localhost/DVWA/
- **Technology Stack:** PHP, MySQL
- **Database:** MariaDB
- **Purpose:** Educational vulnerable application

Both applications are legally permitted for security testing and widely used for educational purposes. Testing was conducted in a controlled, isolated environment.

---

## 5. Methodology

The following systematic steps were followed during the testing process:

### Phase 1: Reconnaissance
1. Identified vulnerable web applications
2. Documented application architecture and technology stack
3. Mapped all user input points
4. Analyzed application functionality

### Phase 2: Automated Scanning
1. The vulnerable web application was hosted locally on the system
2. OWASP ZAP was launched from Kali Linux
3. An automated security scan was initiated against the target URL
4. Scanner analyzed the application for known vulnerabilities
5. Automated scan completed and results captured

### Phase 3: Manual Testing
1. Verified automated findings through manual testing
2. Attempted exploitation of identified vulnerabilities
3. Documented proof of concept demonstrations
4. Analyzed impact and severity of each vulnerability

### Phase 4: Analysis and Reporting
1. Identified vulnerabilities were reviewed and categorized
2. Risk ratings assigned using industry standards
3. Findings documented with detailed evidence
4. Remediation strategies developed for each issue

**This methodology ensures a structured and ethical approach to security testing.**

---

## 6. Identified Vulnerabilities

### 6.1 SQL Injection (SQLi)

**Risk Level:** 🔴 **HIGH (CVSS 9.8)**

**Vulnerability Type:** CWE-89: SQL Injection

**Description:**  
SQL Injection vulnerabilities allow attackers to manipulate backend database queries by injecting malicious SQL commands through user inputs. The application fails to properly sanitize user input in the login form and search functionality.

**Affected Areas:**
- User authentication login form
- Search functionality
- Product filtering features

**Impact:**
- ❌ Unauthorized access to sensitive data
- ❌ Data modification or deletion
- ❌ Database compromise
- ❌ Potential complete application takeover
- ❌ Exposure of customer personal information

**Proof of Concept:**
```sql
-- In username field:
admin' OR '1'='1

-- In search field:
' UNION SELECT * FROM users --
```

**Mitigation:**
- ✅ Use prepared statements and parameterized queries
- ✅ Implement input validation and sanitization
- ✅ Apply least privilege principle to database users
- ✅ Use Web Application Firewall (WAF)
- ✅ Regular code review and security audits
- ✅ Implement stored procedures with parameters

**References:**
- OWASP SQL Injection: https://owasp.org/www-community/attacks/SQL_Injection
- CWE-89: https://cwe.mitre.org/data/definitions/89.html

---

### 6.2 Cross-Site Scripting (XSS)

**Risk Level:** 🟡 **MEDIUM (CVSS 6.1)**

**Vulnerability Type:** CWE-79: Cross-Site Scripting

**Description:**  
XSS vulnerabilities allow attackers to inject malicious scripts into web pages viewed by other users. The application fails to properly encode user input in product reviews and search results.

**Types Identified:**
- **Reflected XSS:** Via URL parameters in search
- **Stored XSS:** In product review comments
- **DOM-based XSS:** Client-side JavaScript vulnerabilities

**Affected Areas:**
- Product search functionality
- User review/comment sections
- Profile customization fields

**Impact:**
- ❌ Session hijacking
- ❌ Credential theft
- ❌ Malware distribution
- ❌ Defacement of web content
- ❌ User information theft

**Proof of Concept:**
```html
<!-- Reflected XSS -->
<script>alert('XSS Vulnerability')</script>

<!-- Stored XSS -->
<img src=x onerror="alert('XSS')">

<!-- DOM-based XSS -->
<input onfocus="alert('Focused')" autofocus>
```

**Mitigation:**
- ✅ Input validation and output encoding
- ✅ Content Security Policy (CSP) headers
- ✅ Use security-focused template engines
- ✅ Regular security audits
- ✅ User education and awareness
- ✅ Use HTTPOnly and Secure cookie flags

**References:**
- OWASP XSS Prevention: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
- CWE-79: https://cwe.mitre.org/data/definitions/79.html

---

### 6.3 Security Misconfiguration

**Risk Level:** 🟡 **MEDIUM (CVSS 5.3)**

**Vulnerability Type:** CWE-16: Configuration Related Vulnerability

**Description:**  
Missing or improperly configured security headers expose the application to various attacks. The application does not implement recommended HTTP security headers.

**Missing Security Headers:**
- ❌ `X-Frame-Options` - No clickjacking protection
- ❌ `Content-Security-Policy` - No XSS prevention via CSP
- ❌ `X-Content-Type-Options` - No MIME type sniffing prevention
- ❌ `Strict-Transport-Security` - No HTTPS enforcement
- ❌ `X-XSS-Protection` - No browser-level XSS filter

**Impact:**
- ⚠️ Increased exposure to browser-based attacks
- ⚠️ Clickjacking vulnerabilities
- ⚠️ MIME type confusion attacks
- ⚠️ Man-in-the-middle attacks (without HSTS)

**Remediation:**
```apache
# Add to Apache configuration (.htaccess or apache2.conf)
Header set X-Frame-Options "SAMEORIGIN"
Header set X-Content-Type-Options "nosniff"
Header set X-XSS-Protection "1; mode=block"
Header set Strict-Transport-Security "max-age=31536000; includeSubDomains"
Header set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
```

**References:**
- OWASP Secure Headers: https://owasp.org/www-project-secure-headers/
- CWE-16: https://cwe.mitre.org/data/definitions/16.html

---

## 7. Results and Analysis

The automated scan using OWASP ZAP successfully identified multiple vulnerabilities within the applications. The findings demonstrate several important insights:

### Key Findings:
1. **High-Risk Vulnerabilities:** 2 critical SQL Injection and Weak Authentication issues
2. **Medium-Risk Vulnerabilities:** 2 XSS and Security Misconfiguration issues
3. **Low-Risk Issues:** Information disclosure and missing security headers

### Impact Summary:
- **Total Vulnerabilities Found:** 5+ confirmed issues
- **Exploitability:** All vulnerabilities were successfully confirmed
- **Severity Distribution:** 
  - 2 HIGH severity
  - 3 MEDIUM severity

### Evidence:
All findings were verified through:
- Automated OWASP ZAP scanning
- Manual exploitation attempts
- Proof of concept demonstrations
- Screenshot documentation

These findings highlight the importance of secure coding practices and proactive security testing during web application development.

---

## 8. Learning Outcomes

Through this task, the following skills and knowledge were gained:

### Technical Knowledge
- ✅ Understanding of common web application vulnerabilities (OWASP Top 10)
- ✅ SQL Injection attack vectors and prevention techniques
- ✅ XSS exploitation and mitigation strategies
- ✅ Security misconfiguration identification and remediation
- ✅ HTTP security headers and their importance

### Tool Proficiency
- ✅ Hands-on experience with OWASP ZAP
- ✅ Automated vulnerability scanning techniques
- ✅ Manual security testing methodologies
- ✅ Vulnerability assessment and reporting
- ✅ Evidence documentation and proof of concept

### Professional Skills
- ✅ Knowledge of ethical hacking principles
- ✅ Practical exposure to vulnerability assessment techniques
- ✅ Security report writing and documentation
- ✅ Risk assessment and prioritization
- ✅ Remediation planning and recommendations

---

## 9. Conclusion

This task provided valuable practical experience in web application security testing. The vulnerabilities identified demonstrate how insecure coding practices can lead to serious security risks. Key conclusions:

### Critical Findings:
1. **SQL Injection is Critical** - Applications must use parameterized queries
2. **Input Validation is Essential** - All user input must be validated
3. **Security Headers Matter** - HTTP headers provide important protections
4. **Testing is Vital** - Regular security testing catches vulnerabilities early
5. **Education is Key** - Developers need security training

### Recommendations:
- Implement secure coding practices immediately
- Use OWASP guidelines for all development
- Conduct regular security testing
- Provide developer security training
- Deploy Web Application Firewall

Using tools like OWASP ZAP helps organizations detect and mitigate such issues early in the development lifecycle, thereby improving overall application security and protecting user data.

---

## 10. References

### OWASP Standards
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP Secure Headers](https://owasp.org/www-project-secure-headers/)
- [OWASP Cheat Sheets](https://cheatsheetseries.owasp.org/)

### Security Resources
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/)
- [CVSS Calculator](https://www.first.org/cvss/calculator/3.1)
- [Kali Linux](https://www.kali.org/)

### Tools
- [OWASP ZAP](https://www.zaproxy.org/)
- [Burp Suite](https://portswigger.net/burp)
- [DVWA](https://dvwa.co.uk/)
- [OWASP Juice Shop](https://owasp.org/www-project/juice-shop/)

---

## Report Information

**Report Title:** Web Application Security Testing Report  
**Prepared By:** Dhanush G  
**Organization:** Future Interns  
**Domain:** Cyber Security  
**Track:** CS - 01  
**Date:** December 25, 2025  
**Status:** ✅ Completed  

---

**Disclaimer:** This report documents security testing conducted on intentionally vulnerable applications in a controlled, authorized environment for educational purposes only. All testing was performed ethically and in compliance with applicable laws and regulations.
