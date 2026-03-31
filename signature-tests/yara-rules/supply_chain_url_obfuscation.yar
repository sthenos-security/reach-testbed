/*
 * REACHABLE YARA Rules — Runtime URL Obfuscation Detection
 * supply_chain_url_obfuscation.yar
 *
 * Covers all techniques in malware-test-packages/ and static-malware-tests/:
 *
 *   T1  base64-encoded C2 URL              (fake-b64-c2-url, fake-litellm-b64-c2)
 *   T2  XOR-encoded C2 URL                 (fake-xor-c2-url, fake-xor-c2)
 *   T3  chr()/fromCharCode array URL       (fake-chr-array-c2, fake-chr-sequence-c2)
 *   T4  AES-CTR encrypted URL              (fake-aes-decrypt-c2)
 *   T5  zlib+base64 multi-layer            (fake-zlib-b64-c2)
 *   T6  DNS long-subdomain exfil           (fake-dns-long-subdomain, fake-dns-subdomain-exfil)
 *   T7  Legitimate cloud service as C2     (fake-legit-domain-c2)
 *   T8  Known TeamPCP IOC strings          (litellm b64 literal, checkmarx.zone)
 *
 * Principle: static rules detect the ENCODING MECHANISM + NETWORK ACTION pair.
 * The destination domain is irrelevant — obfuscation is the signal.
 * Dynamic sandbox catches the plaintext destination at socket time regardless.
 *
 * Author: REACHABLE Security (Sthenos Security)
 * Version: 1.0 — 2026-03-31
 */

// =============================================================================
// T1: Base64-encoded C2 URL
// =============================================================================

rule SupplyChain_B64_URL_Decode_Network {
    meta:
        description = "Base64 decode followed by network call — C2 URL obfuscation"
        technique   = "T1-base64-url"
        severity    = "critical"
        real_world  = "LiteLLM v1.82.7/1.82.8 (TeamPCP, March 2026)"
        testcase    = "fake-b64-c2-url, fake-litellm-b64-c2"
    strings:
        // Python: base64.b64decode(...)
        $py_b64d  = "b64decode"          ascii
        $py_req   = "requests.post"      ascii
        $py_url   = "urllib.request"     ascii
        $py_open  = "urlopen"            ascii
        // Node.js: Buffer.from(..., 'base64')
        $js_buf   = "Buffer.from"        ascii
        $js_b64   = "'base64'"           ascii
        $js_https = "https.request"      ascii
        $js_http  = "http.request"       ascii
        // Generic: exec(base64.b64decode(...))
        $exec_b64 = /exec\s*\(\s*base64/ ascii
    condition:
        // Python: decode + any network call
        ($py_b64d and (1 of ($py_req, $py_url, $py_open))) or
        // Node: Buffer.from + 'base64' + network
        ($js_buf and $js_b64 and (1 of ($js_https, $js_http))) or
        // Exec chain
        $exec_b64
}

rule SupplyChain_TeamPCP_IOC_B64 {
    meta:
        description = "TeamPCP campaign: known C2 domain encoded as base64 literal"
        technique   = "T1-base64-url"
        severity    = "critical"
        real_world  = "LiteLLM supply chain attack, March 2026"
        testcase    = "fake-b64-c2-url, fake-litellm-b64-c2, fake-chr-array-c2"
        ioc         = "models.litellm.cloud, checkmarx.zone"
    strings:
        // base64("https://models.litellm.cloud/upload") — exact TeamPCP literal
        $b64_primary   = "aHR0cHM6Ly9tb2RlbHMubGl0ZWxsbS5jbG91ZC91cGxvYWQ=" ascii
        // base64("https://checkmarx.zone/collect") — confirmed secondary C2
        $b64_secondary = "aHR0cHM6Ly9jaGVja21hcnoem9uZS9jb2xsZWN0"           ascii
        // Plaintext domain in case obfuscation is absent
        $plain_primary   = "models.litellm.cloud"   ascii
        $plain_secondary = "checkmarx.zone"          ascii
        // Double-encoded outer layer
        $b64_double = "YUhSMGNITTZMeTl0YjJSbGJHeHZMbXhwZEdWc2FJSE"          ascii
    condition:
        any of them
}

// =============================================================================
// T2: XOR-encoded C2 URL
// =============================================================================

rule SupplyChain_XOR_URL_Decode_Network {
    meta:
        description = "XOR decode loop followed by network call — C2 URL obfuscation"
        technique   = "T2-xor-url"
        severity    = "critical"
        real_world  = "plain-crypto-js@4.2.1 XOR key 'OrDeR_7077'"
        testcase    = "fake-xor-c2-url, fake-xor-c2"
    strings:
        // Python: byte XOR loop patterns
        $py_xor1  = /bytes\(b\s*\^\s*key/ ascii
        $py_xor2  = /for\s+b\s+in\s+data.*\^\s*key/ ascii
        $py_xor3  = /map\(lambda\s+b.*\^/ ascii
        // Python: bytes.fromhex + XOR
        $py_hex   = "bytes.fromhex"      ascii
        $py_dec   = ".decode("           ascii
        // Node.js: Buffer XOR map
        $js_xor1  = /buf\.map\(\(b,\s*i\)\s*=>\s*b\s*\^/ ascii
        $js_xor2  = /\.map\(b\s*=>\s*b\s*\^/ ascii
        // Network call in same file
        $py_net   = "urlopen"            ascii
        $py_req   = "urllib.request"     ascii
        $js_https = "https.request"      ascii
        $js_net   = "net.Socket"         ascii
        // Real key material from plain-crypto-js
        $xor_key  = "OrDeR_7077"         ascii
        $xor_key2 = "6202033"            ascii  // campaign ID
    condition:
        ($xor_key or $xor_key2) or
        (($py_xor1 or $py_xor2 or $py_xor3) and $py_hex and (1 of ($py_net, $py_req))) or
        (($js_xor1 or $js_xor2) and (1 of ($js_https, $js_net)))
}

rule SupplyChain_IE8_UserAgent {
    meta:
        description = "IE8 User-Agent string — real TeamPCP/plain-crypto-js C2 fingerprint"
        technique   = "T2-xor-url"
        severity    = "critical"
        real_world  = "plain-crypto-js C2 traffic; Huntress confirmed March 2026"
        testcase    = "fake-xor-c2-url"
        ioc         = "mozilla/4.0 (compatible; msie 8.0; windows nt 5.1)"
    strings:
        $ie8 = "msie 8.0" nocase ascii
        $xp  = "windows nt 5.1" nocase ascii
    condition:
        $ie8 and $xp
}

// =============================================================================
// T3: chr() / String.fromCharCode array URL
// =============================================================================

rule SupplyChain_CharCode_Array_URL {
    meta:
        description = "URL assembled from chr()/fromCharCode integer arrays — no string literal"
        technique   = "T3-charcode-url"
        severity    = "critical"
        real_world  = "multiple npm/PyPI campaigns 2022-2025"
        testcase    = "fake-chr-array-c2, fake-chr-sequence-c2"
    strings:
        // Node.js: String.fromCharCode with sequential args
        $js_fcc  = "String.fromCharCode"               ascii
        // Python: chr() concatenation — multiple sequential chr() calls
        $py_chr1 = /chr\(\d+\)\s*\+\s*chr\(\d+\)\s*\+\s*chr\(\d+\)/ ascii
        // Python: URL-typical chr codes: chr(104)=h, chr(116)=t, chr(58)=:
        $py_h    = "chr(104)"   ascii   // 'h' — start of https
        $py_t    = "chr(116)"   ascii   // 't'
        $py_colon = "chr(58)"   ascii   // ':'
        $py_slash = "chr(47)"   ascii   // '/'
        // Network calls
        $py_post = "urllib.request"  ascii
        $py_req  = "requests.post"   ascii
        $js_req  = "https.request"   ascii
        $js_req2 = "http.request"    ascii
    condition:
        ($js_fcc and (1 of ($js_req, $js_req2))) or
        ($py_chr1 and (1 of ($py_post, $py_req))) or
        // Characteristic cluster: h, t, :, / together = URL from chrcodes
        (3 of ($py_h, $py_t, $py_colon, $py_slash) and (1 of ($py_post, $py_req)))
}

// =============================================================================
// T4: AES-encrypted C2 URL
// =============================================================================

rule SupplyChain_AES_Hardcoded_Key_Network {
    meta:
        description = "Hardcoded AES key/nonce + network call — encrypted C2 URL"
        technique   = "T4-aes-url"
        severity    = "critical"
        real_world  = "Advanced PyPI infostealers (2024-2025)"
        testcase    = "fake-aes-decrypt-c2"
    strings:
        // Python: AES.new() with MODE_CTR or MODE_CBC
        $py_aes1  = "AES.new("      ascii
        $py_ctr   = "MODE_CTR"      ascii
        $py_cbc   = "MODE_CBC"      ascii
        $py_gcm   = "MODE_GCM"      ascii
        // Crypto imports
        $py_imp1  = "from Crypto.Cipher import AES"  ascii
        $py_imp2  = "from cryptography"              ascii
        // Node.js: AES via crypto module
        $js_aes1  = "createDecipheriv" ascii
        $js_aes2  = "'aes-128-ctr'"    ascii
        $js_aes3  = "'aes-256-cbc'"    ascii
        // Hardcoded key bytes — 16-byte (128-bit) key as bytes literal
        $key_py   = /b'[\\x][0-9a-fA-F]{2}([\\x][0-9a-fA-F]{2}){14,}'/ ascii
        // Network call in same file
        $py_net   = "urlopen"           ascii
        $py_req   = "requests.post"     ascii
        $js_https = "https.request"     ascii
    condition:
        (($py_aes1 or $py_imp1 or $py_imp2) and
         (1 of ($py_ctr, $py_cbc, $py_gcm)) and
         (1 of ($py_net, $py_req))) or
        ($js_aes1 and (1 of ($js_aes2, $js_aes3)) and $js_https)
}

// =============================================================================
// T5: zlib + base64 multi-layer
// =============================================================================

rule SupplyChain_MultiLayer_ZlibB64_Network {
    meta:
        description = "zlib.decompress(base64.b64decode(blob)) + network call"
        technique   = "T5-zlib-b64"
        severity    = "critical"
        real_world  = "Muad'Dib pattern; common in PyPI second-stage droppers"
        testcase    = "fake-zlib-b64-c2"
    strings:
        $py_zlib   = "zlib.decompress"  ascii
        $py_b64d   = "b64decode"        ascii
        $py_exec   = "exec("            ascii
        $py_net    = "urlopen"          ascii
        $py_req    = "requests.post"    ascii
        // Node.js: zlib equivalent
        $js_zlib   = "require('zlib')"  ascii
        $js_inflate = "inflate"         ascii
        $js_b64    = "'base64'"         ascii
    condition:
        ($py_zlib and $py_b64d and (1 of ($py_net, $py_req, $py_exec))) or
        ($js_zlib and $js_inflate and $js_b64)
}

// =============================================================================
// T6: DNS long-subdomain exfil
// =============================================================================

rule SupplyChain_DNS_Subdomain_Exfil {
    meta:
        description = "DNS covert channel — credential data encoded in long subdomains"
        technique   = "T6-dns-subdomain"
        severity    = "critical"
        real_world  = "Muad'Dib Stage 5; plain-crypto-js Stage 6; multiple campaigns"
        testcase    = "fake-dns-long-subdomain, fake-dns-subdomain-exfil, fake-dns-exfil"
        note        = "Dynamic sandbox classifies dns_lookup with label >32 chars as CRITICAL"
    strings:
        // Python: socket.getaddrinfo in a loop (chunked exfil)
        $py_dns1  = "socket.getaddrinfo"    ascii
        $py_loop  = "for"                   ascii
        $py_b32   = "base32encode"          ascii
        $py_b32_2 = "b32encode"             ascii
        $py_chunk = "CHUNK_SIZE"            ascii
        $py_chunk2 = "chunk"               ascii
        // Node.js: dns.resolve in a loop
        $js_dns1  = "dns.resolve"           ascii
        $js_dns2  = "dns.lookup"            ascii
        $js_b32   = "base32"               ascii
        $js_chunk = "chunk"                ascii
        // Common: dns-exfil domain pattern
        $dns_dom1 = "dns-exfil"            ascii
        $dns_dom2 = ".dns."               ascii
        // Harvest + DNS combination
        $harvest  = ".aws/credentials"     ascii
        $harvest2 = "GITHUB_TOKEN"         ascii
    condition:
        // Python DNS exfil loop
        ($py_dns1 and $py_loop and (1 of ($py_b32, $py_b32_2, $py_chunk))) or
        // Node DNS exfil loop
        ($js_dns1 and $js_chunk) or
        // Domain pattern + harvest = confirmed DNS exfil
        ((1 of ($dns_dom1, $dns_dom2)) and (1 of ($harvest, $harvest2))) or
        // Explicit dns-exfil domain in source
        $dns_dom1
}

// =============================================================================
// T7: Legitimate cloud service as C2 dead drop
// =============================================================================

rule SupplyChain_LegitDomain_Exfil_GithubGist {
    meta:
        description = "GitHub Gist API POST from install hook — legitimate-domain C2"
        technique   = "T7-legit-domain"
        severity    = "critical"
        real_world  = "Multiple npm/PyPI campaigns 2023-2024"
        testcase    = "fake-legit-domain-c2"
        note        = "github.com removed from sandbox allowed_hosts for this reason"
    strings:
        $gist_path = "/gists"            ascii
        $gh_api    = "api.github.com"   ascii
        $gh_auth   = "Authorization"    ascii
        $token_pfx = "token ghp_"       ascii nocase
        $token_pfx2 = "Bearer ghp_"     ascii nocase
        $harvest   = ".aws/credentials" ascii
        $harvest2  = "GITHUB_TOKEN"      ascii
        $harvest3  = "id_rsa"            ascii
    condition:
        ($gist_path and $gh_api) or
        ($gh_api and $gh_auth and (1 of ($harvest, $harvest2, $harvest3)))
}

rule SupplyChain_LegitDomain_Exfil_Discord {
    meta:
        description = "Discord webhook POST from install hook — legitimate-domain C2"
        technique   = "T7-legit-domain"
        severity    = "critical"
        real_world  = "npm/PyPI campaigns 2022-2025; common in info-stealer droppers"
        testcase    = "fake-legit-domain-c2"
    strings:
        $discord_wh = "discord.com/api/webhooks" ascii
        $discord_wh2 = "discordapp.com/api/webhooks" ascii
        $discord_api = "discord.com"               ascii
        $harvest    = ".aws/credentials"           ascii
        $harvest2   = "GITHUB_TOKEN"               ascii
        $harvest3   = "SSH_KEY"                    ascii
        $harvest4   = "id_rsa"                     ascii
    condition:
        ($discord_wh or $discord_wh2) or
        ($discord_api and (2 of ($harvest, $harvest2, $harvest3, $harvest4)))
}

rule SupplyChain_LegitDomain_Exfil_Telegram {
    meta:
        description = "Telegram bot API POST from install hook — legitimate-domain C2"
        technique   = "T7-legit-domain"
        severity    = "critical"
        real_world  = "PyPI campaigns 2023-2025"
        testcase    = "fake-legit-domain-c2"
    strings:
        $tg_api   = "api.telegram.org"  ascii
        $tg_send  = "sendMessage"       ascii
        $tg_bot   = "/bot"              ascii
        $harvest  = ".aws/credentials"  ascii
        $harvest2 = "GITHUB_TOKEN"      ascii
    condition:
        ($tg_api and $tg_send) or
        ($tg_api and (1 of ($harvest, $harvest2)))
}

rule SupplyChain_LegitDomain_Exfil_S3 {
    meta:
        description = "S3 PUT from install hook — legitimate-domain C2 (attacker-owned bucket)"
        technique   = "T7-legit-domain"
        severity    = "critical"
        real_world  = "Advanced supply chain attacks (2024-2025)"
        testcase    = "fake-legit-domain-c2"
    strings:
        $s3_host   = "s3.amazonaws.com"  ascii
        $s3_acl    = "public-read"       ascii
        $s3_put    = "PUT"               ascii
        $harvest   = ".aws/credentials"  ascii
        $harvest2  = "GITHUB_TOKEN"      ascii
        $harvest3  = "id_rsa"            ascii
    condition:
        ($s3_host and $s3_acl) or
        ($s3_host and $s3_put and (1 of ($harvest, $harvest2, $harvest3)))
}

// =============================================================================
// T8: Mass credential harvest pattern (present across all techniques)
// =============================================================================

rule SupplyChain_MassCredentialHarvest {
    meta:
        description = "5+ credential file paths in one file — mass credential harvester"
        technique   = "T8-harvest"
        severity    = "critical"
        real_world  = "TeamPCP/LiteLLM, ctx, ultrarequests, dozens of PyPI attacks"
        testcase    = "fake-litellm-b64-c2, fake-legit-domain-c2, muaddib-simulation"
        note        = "Legitimate packages never enumerate 5+ credential stores"
    strings:
        $cred1 = ".aws/credentials"           ascii
        $cred2 = ".ssh/id_rsa"                ascii
        $cred3 = ".ssh/id_ed25519"            ascii
        $cred4 = ".npmrc"                     ascii
        $cred5 = ".pypirc"                    ascii
        $cred6 = ".netrc"                     ascii
        $cred7 = ".docker/config.json"        ascii
        $cred8 = ".kube/config"               ascii
        $cred9 = ".git-credentials"           ascii
        $cred10 = "gcloud/credentials"        ascii
    condition:
        5 of ($cred*)
}

rule SupplyChain_EnvVar_Mass_Harvest {
    meta:
        description = "5+ high-value env var names in one file — mass env harvester"
        technique   = "T8-harvest"
        severity    = "critical"
        real_world  = "ctx package (real PyPI attack), LiteLLM, dozens of others"
        testcase    = "fake-litellm-b64-c2, fake-legit-domain-c2"
    strings:
        $env1  = "AWS_ACCESS_KEY_ID"      ascii
        $env2  = "AWS_SECRET_ACCESS_KEY"  ascii
        $env3  = "GITHUB_TOKEN"           ascii
        $env4  = "NPM_TOKEN"              ascii
        $env5  = "PYPI_TOKEN"             ascii
        $env6  = "OPENAI_API_KEY"         ascii
        $env7  = "ANTHROPIC_API_KEY"      ascii
        $env8  = "STRIPE_SECRET_KEY"      ascii
        $env9  = "DATABASE_URL"           ascii
        $env10 = "CI_JOB_TOKEN"           ascii
        $env11 = "GITLAB_TOKEN"           ascii
        $env12 = "DISCORD_WEBHOOK"        ascii
    condition:
        5 of ($env*)
}

rule SupplyChain_EncryptedExfil {
    meta:
        description = "RSA/AES encrypt then POST — encrypted exfil (LiteLLM pattern)"
        technique   = "T8-encrypted-exfil"
        severity    = "critical"
        real_world  = "LiteLLM v1.82.7/1.82.8 — RSA-4096-OAEP then POST"
        testcase    = "fake-litellm-b64-c2, litellm_metadata_service.py"
    strings:
        $rsa1 = "RSA.import_key"         ascii
        $rsa2 = "RSA.generate"           ascii
        $rsa3 = "PKCS1_OAEP"             ascii
        $rsa4 = "-----BEGIN PUBLIC KEY" ascii
        $post1 = "requests.post"         ascii
        $post2 = "urlopen"               ascii
        $post3 = "https.request"         ascii
        $tarf  = "tarfile.open"          ascii
    condition:
        (1 of ($rsa*)) and (1 of ($post*))
}

// =============================================================================
// Meta rule: any supply chain obfuscation
// =============================================================================

rule SupplyChain_URL_Obfuscation_Any {
    meta:
        description = "Any URL obfuscation technique detected in install hook context"
        severity    = "critical"
    condition:
        SupplyChain_B64_URL_Decode_Network       or
        SupplyChain_TeamPCP_IOC_B64              or
        SupplyChain_XOR_URL_Decode_Network       or
        SupplyChain_IE8_UserAgent                or
        SupplyChain_CharCode_Array_URL           or
        SupplyChain_AES_Hardcoded_Key_Network    or
        SupplyChain_MultiLayer_ZlibB64_Network   or
        SupplyChain_DNS_Subdomain_Exfil          or
        SupplyChain_LegitDomain_Exfil_GithubGist or
        SupplyChain_LegitDomain_Exfil_Discord    or
        SupplyChain_LegitDomain_Exfil_Telegram   or
        SupplyChain_LegitDomain_Exfil_S3         or
        SupplyChain_MassCredentialHarvest        or
        SupplyChain_EnvVar_Mass_Harvest          or
        SupplyChain_EncryptedExfil
}
