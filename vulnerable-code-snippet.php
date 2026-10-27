<?php
/**
 * Vulnerable Code Snippet from RainLab User Plugin
 * File: components/Session.php
 *
 * This demonstrates the Open Redirect vulnerability
 * DO NOT USE IN PRODUCTION
 */

// ============================================
// VULNERABLE CODE - Location 1 (Lines 168-170)
// ============================================

/**
 * Log the user out - VULNERABLE
 */
public function onLogout()
{
    if ($event = $this->actions()->logout()) {
        return $event;
    }

    if ($flash = Cms::flashFromPost(__("You have been successfully logged out!"))) {
        Flash::success($flash);
    }

    // VULNERABLE: No validation of redirect URL!
    // User-supplied POST data passed directly to Redirect::to()
    if ($redirectUrl = post('redirect', Request::fullUrl())) {
        return Redirect::to($redirectUrl);  // <-- VULNERABILITY HERE
    }
}

// ============================================
// VULNERABLE CODE - Location 2 (Lines 314-320)
// ============================================

/**
 * Stop impersonating a user - VULNERABLE
 */
public function onStopImpersonating()
{
    if (!$this->impersonator()) {
        return $this->onLogout();
    }

    Auth::stopImpersonate();

    // VULNERABLE: No validation of redirect URL!
    $url = post('redirect', Request::fullUrl());

    if ($flash = Cms::flashFromPost(__("You are no longer impersonating a user."))) {
        Flash::success($flash);
    }

    return Redirect::to($url);  // <-- VULNERABILITY HERE
}

// ============================================
// FIXED CODE - Recommended Remediation
// ============================================

/**
 * Check if URL is local/same-origin
 */
private function isLocalUrl($url)
{
    // Empty or null is safe (will use default)
    if (empty($url)) {
        return true;
    }

    // Block javascript: and data: URIs
    $scheme = parse_url($url, PHP_URL_SCHEME);
    if ($scheme && !in_array(strtolower($scheme), ['http', 'https'], true)) {
        return false;
    }

    // Relative URLs are safe
    $parsed = parse_url($url);
    if (empty($parsed['host'])) {
        return true;
    }

    // Check if same host
    return strcasecmp($parsed['host'], Request::getHost()) === 0;
}

/**
 * Fixed onLogout method
 */
public function onLogoutFixed()
{
    if ($event = $this->actions()->logout()) {
        return $event;
    }

    if ($flash = Cms::flashFromPost(__("You have been successfully logged out!"))) {
        Flash::success($flash);
    }

    if ($redirectUrl = post('redirect', Request::fullUrl())) {
        // FIXED: Validate redirect URL before use
        if ($this->isLocalUrl($redirectUrl)) {
            return Redirect::to($redirectUrl);
        }
        // Fallback to homepage if invalid
        return Redirect::to('/');
    }
}
