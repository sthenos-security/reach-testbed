// Copyright © 2026 Sthenos Security. All rights reserved.
// =============================================================================
// REACHABLE TEST FILE — DO NOT USE IN PRODUCTION
// Framework: React (client-side)
//
// IMPORTANT: React is a CLIENT-SIDE framework. There are no HTTP server
// entrypoints and no server-side call graph. Signal model is different:
//
//   SERVER-SIDE:  HTTP route → function → sink  (reachability via call graph)
//   CLIENT-SIDE:  component render / event handler → sink  (all rendered
//                 components are "reachable" — attacker controls URL/input)
//
// For React, reachability means:
//   REACHABLE   = component is rendered (mounted) / event handler is wired
//   NOT_REACHABLE = component never rendered, dead export
//
// Signal categories tested here:
//   CWE-79   XSS via dangerouslySetInnerHTML
//   CWE-79   XSS via DOM direct write (document.write, innerHTML)
//   CWE-312  Cleartext storage of sensitive data (localStorage/sessionStorage)
//   DLP      PII sent to third-party analytics
//   SECRET   Hardcoded API keys in client bundle (shipped to browser)
//   CWE-601  Open redirect via window.location
//   CWE-346  Cross-origin message injection (postMessage)
// =============================================================================

import React, { useEffect, useRef, useState } from 'react';

// =============================================================================
// SECRETS — hardcoded in client bundle, shipped to every browser
// These are TRUE POSITIVES regardless of reachability (always in bundle).
// =============================================================================

const STRIPE_PK  = 'pk_live_51Abc123xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';  // SECRET TP
const GA_API_KEY = 'AIzaSyD-9tSrke72I7lsh1XXXXXXXXXXXXXXXXXX';             // SECRET TP
const MIXPANEL_TOKEN = 'abc123def456abc123def456abc123de';                   // SECRET TP
const SENTRY_DSN = 'https://abc123@o123456.ingest.sentry.io/123456';        // SECRET (debatable — public DSN)
// Safe — not a secret, just a public URL
const API_BASE_URL = 'https://api.myapp.com';


// =============================================================================
// CWE-79: XSS — dangerouslySetInnerHTML with user-controlled input
//
// Reachability: all components below are RENDERED (mounted in App).
// The question is whether user input (props, URL params, fetched data)
// flows into the dangerous sink.
// =============================================================================

/**
 * TP: dangerouslySetInnerHTML with content from URL search param — REACHABLE.
 * Call path: URL ?msg=... → URLSearchParams → dangerouslySetInnerHTML
 */
function XSSFromURLParam() {
  const msg = new URLSearchParams(window.location.search).get('msg') || '';
  return (
    <div
      dangerouslySetInnerHTML={{ __html: msg }}  // CWE-79 TP
    />
  );
}

/**
 * TP: dangerouslySetInnerHTML with content from API response — REACHABLE.
 * Attacker controls server response (stored XSS scenario).
 */
function XSSFromAPIResponse({ postId }) {
  const [content, setContent] = useState('');
  useEffect(() => {
    fetch(`${API_BASE_URL}/posts/${postId}`)
      .then(r => r.json())
      .then(data => setContent(data.htmlContent));  // trusting server HTML
  }, [postId]);
  return (
    <article dangerouslySetInnerHTML={{ __html: content }} />  // CWE-79 TP
  );
}

/**
 * TP: dangerouslySetInnerHTML with content from props — REACHABLE.
 * Props come from parent; if parent passes user input this is XSS.
 */
function XSSFromProps({ userBio }) {
  return (
    <div dangerouslySetInnerHTML={{ __html: userBio }} />  // CWE-79 TP
  );
}

/**
 * FP: dangerouslySetInnerHTML with sanitized content (DOMPurify) — REACHABLE but safe.
 * Engine should note sanitization library is present.
 */
function XSSSanitized({ rawHtml }) {
  // In real code: import DOMPurify from 'dompurify'; const clean = DOMPurify.sanitize(rawHtml);
  const DOMPurify = { sanitize: (x) => x }; // mock for testbed
  const clean = DOMPurify.sanitize(rawHtml);
  return (
    <div dangerouslySetInnerHTML={{ __html: clean }} />  // CWE-79 FP — sanitized
  );
}

/**
 * FP: dangerouslySetInnerHTML with hardcoded string — REACHABLE but NOT injectable.
 */
function XSSHardcoded() {
  return (
    <div dangerouslySetInnerHTML={{ __html: '<strong>Hello</strong>' }} />  // FP
  );
}

/**
 * NOT_REACHABLE: exported but never imported or used in App.
 */
export function XSSDeadComponent({ content }) {
  return <div dangerouslySetInnerHTML={{ __html: content }} />;  // CWE-79 — NOT_REACHABLE
}


// =============================================================================
// CWE-79: Direct DOM manipulation (bypasses React's escaping entirely)
// =============================================================================

/**
 * TP: innerHTML with user input — REACHABLE via event handler.
 */
function DirectDOMWrite() {
  const divRef = useRef(null);
  const handleSearch = (e) => {
    const query = e.target.value;
    // Direct innerHTML assignment — bypasses React, CWE-79 TP
    if (divRef.current) {
      divRef.current.innerHTML = `Results for: ${query}`;  // CWE-79 TP
    }
  };
  return (
    <div>
      <input onChange={handleSearch} placeholder="Search..." />
      <div ref={divRef} />
    </div>
  );
}

/**
 * TP: document.write with URL hash — REACHABLE, rarely sanitized.
 */
function DocWrite() {
  useEffect(() => {
    const hash = window.location.hash.slice(1);
    document.write(`<h1>${hash}</h1>`);  // CWE-79 TP — document.write with attacker-controlled hash
  }, []);
  return <div />;
}


// =============================================================================
// CWE-312 + DLP: Sensitive data in localStorage / sessionStorage
// =============================================================================

/**
 * TP: JWT / auth token stored in localStorage — REACHABLE.
 * localStorage is accessible to any script on the page (XSS pivot).
 */
function InsecureTokenStorage({ token }) {
  useEffect(() => {
    localStorage.setItem('auth_token', token);         // DLP TP — auth token in localStorage
    localStorage.setItem('user_email', 'user@example.com');  // DLP TP — PII in localStorage
    sessionStorage.setItem('credit_card', '4111-1111-1111-1111');  // DLP TP — PCI in sessionStorage
  }, [token]);
  return <div />;
}

/**
 * FP: non-sensitive preference in localStorage — REACHABLE but not DLP.
 */
function SafeLocalStorage() {
  useEffect(() => {
    localStorage.setItem('theme', 'dark');     // FP — not sensitive
    localStorage.setItem('language', 'en');    // FP — not sensitive
  }, []);
  return <div />;
}


// =============================================================================
// DLP: PII sent to third-party analytics
// =============================================================================

/**
 * TP: user email + IP sent to Mixpanel — REACHABLE.
 * Mixpanel/GA/etc. calls with PII are DLP violations depending on policy.
 */
function AnalyticsPIILeak({ user }) {
  useEffect(() => {
    // DLP TP — PII sent to third-party analytics
    if (window.mixpanel) {
      window.mixpanel.identify(user.id);
      window.mixpanel.people.set({
        $email:    user.email,      // DLP TP — email to third party
        $phone:    user.phone,      // DLP TP — phone to third party
        $name:     user.fullName,
        credit_card: user.cardNumber,  // DLP TP — PCI to third party
      });
    }
    // GA4 user properties with PII
    if (window.gtag) {
      window.gtag('set', 'user_properties', {
        user_email: user.email,    // DLP TP — PII in GA4
        user_id: user.ssn,         // DLP TP — SSN in analytics
      });
    }
  }, [user]);
  return <div />;
}


// =============================================================================
// CWE-601: Open redirect via window.location
// =============================================================================

/**
 * TP: open redirect — user-controlled URL from query param — REACHABLE.
 */
function OpenRedirect() {
  const handleRedirect = () => {
    const next = new URLSearchParams(window.location.search).get('next');
    window.location.href = next;  // CWE-601 TP — unvalidated redirect
  };
  return <button onClick={handleRedirect}>Continue</button>;
}

/**
 * FP: redirect to internal path only — REACHABLE but not exploitable.
 */
function SafeRedirect() {
  const handleRedirect = () => {
    const page = new URLSearchParams(window.location.search).get('page');
    const safe = ['/home', '/profile', '/settings'].includes(page) ? page : '/home';
    window.location.pathname = safe;  // FP — allowlist validated
  };
  return <button onClick={handleRedirect}>Go</button>;
}


// =============================================================================
// CWE-346: postMessage injection — trusting messages from any origin
// =============================================================================

/**
 * TP: postMessage handler without origin check — REACHABLE.
 * Any window (including attacker iframe) can send arbitrary messages.
 */
function PostMessageUnsafe() {
  useEffect(() => {
    const handler = (event) => {
      // CWE-346 TP — no origin check, trusting event.data directly
      document.getElementById('output').innerHTML = event.data.html;  // also CWE-79
    };
    window.addEventListener('message', handler);
    return () => window.removeEventListener('message', handler);
  }, []);
  return <div id="output" />;
}

/**
 * FP: postMessage handler with origin validation — REACHABLE but safe.
 */
function PostMessageSafe() {
  useEffect(() => {
    const handler = (event) => {
      if (event.origin !== 'https://trusted.example.com') return;  // FP — origin validated
      console.log('Trusted message:', event.data);
    };
    window.addEventListener('message', handler);
    return () => window.removeEventListener('message', handler);
  }, []);
  return <div />;
}


// =============================================================================
// App — mounts all REACHABLE components
// Dead exports above (XSSDeadComponent) are excluded from this tree.
// =============================================================================

export default function App() {
  const mockUser = {
    id: '123', email: 'user@example.com', phone: '555-1234',
    fullName: 'Test User', cardNumber: '4111111111111111', ssn: '123-45-6789'
  };

  return (
    <div>
      <XSSFromURLParam />
      <XSSFromAPIResponse postId="1" />
      <XSSFromProps userBio="<b>Hello</b>" />
      <XSSSanitized rawHtml="<p>safe</p>" />
      <XSSHardcoded />
      <DirectDOMWrite />
      <DocWrite />
      <InsecureTokenStorage token="eyJhbGciOiJIUzI1NiJ9.test" />
      <SafeLocalStorage />
      <AnalyticsPIILeak user={mockUser} />
      <OpenRedirect />
      <SafeRedirect />
      <PostMessageUnsafe />
      <PostMessageSafe />
    </div>
  );
}
