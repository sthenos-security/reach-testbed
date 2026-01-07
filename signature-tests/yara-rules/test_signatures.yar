/*
 * REACHABLE Test Signatures - YARA Rules
 * 
 * These rules detect safe, non-malicious test signatures used to validate
 * REACHABLE's detection and reachability filtering pipeline.
 * 
 * Usage:
 *   yara -r test_signatures.yar /path/to/scan
 */

rule EICAR_Test_Signature {
    meta:
        description = "EICAR antivirus test file - industry standard test signature"
        author = "REACHABLE Security"
        reference = "https://www.eicar.org/download-anti-malware-testfile/"
        severity = "test"
        
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        $eicar_partial = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
        
    condition:
        any of them
}

rule Test_Malware_Marker {
    meta:
        description = "Synthetic test malware marker for pipeline validation"
        author = "REACHABLE Security"
        severity = "test"
        
    strings:
        $marker1 = "TEST-MALWARE-SIGNATURE-12345"
        $marker2 = "REACHABLE-TEST-MARKER"
        
    condition:
        any of them
}

rule Test_Ransomware_Pattern {
    meta:
        description = "Fake ransomware marker for detection testing"
        author = "REACHABLE Security"
        severity = "test"
        
    strings:
        $ransom1 = "FAKE_RANSOMWARE_MARKER::ENCRYPT_START"
        $ransom2 = "FAKE_RANSOMWARE_MARKER::DECRYPT_KEY"
        $ransom3 = "YOUR_FILES_ARE_ENCRYPTED_TEST"
        
    condition:
        any of them
}

rule Test_Command_Injection {
    meta:
        description = "Simulated command injection pattern"
        author = "REACHABLE Security"
        severity = "test"
        
    strings:
        $cmd1 = "CMD_EXEC_SIMULATION"
        $cmd2 = "SHELL_INJECT_TEST"
        $cmd3 = /; *rm -rf \/fake\/path/
        
    condition:
        any of them
}

rule Test_C2_Beacon {
    meta:
        description = "Simulated C2 beacon callback pattern"
        author = "REACHABLE Security"
        severity = "test"
        
    strings:
        $c2_1 = "REACHABLE_TEST_BEACON::C2_CALLBACK"
        $c2_2 = "TEST_BEACON_CHECKIN"
        $c2_3 = /https?:\/\/[a-z0-9-]+\.attacker\.test/
        $c2_4 = /https?:\/\/c2\.[a-z0-9-]+\.test/
        
    condition:
        any of them
}

rule Test_Crypto_Miner {
    meta:
        description = "Simulated cryptominer pool connection"
        author = "REACHABLE Security"
        severity = "test"
        
    strings:
        $pool1 = "CRYPTO_MINER_POOL::stratum+tcp://test.pool"
        $pool2 = "stratum+tcp://mine.fake-pool.test"
        $pool3 = "xmrig-test-config"
        
    condition:
        any of them
}

rule Test_Data_Exfiltration {
    meta:
        description = "Simulated data exfiltration pattern"
        author = "REACHABLE Security"
        severity = "test"
        
    strings:
        $exfil1 = "EXFIL_TEST_MARKER"
        $exfil2 = /exfil\.[a-z0-9-]+\.test/
        $exfil3 = "DATA_THEFT_SIMULATION"
        
    condition:
        any of them
}

rule Test_Credential_Harvester {
    meta:
        description = "Simulated credential harvesting pattern"
        author = "REACHABLE Security"
        severity = "test"
        
    strings:
        $cred1 = "CREDENTIAL_HARVEST_TEST"
        $cred2 = "STEAL_NPMRC_TEST"
        $cred3 = "SSH_KEY_THEFT_SIMULATION"
        
    condition:
        any of them
}

rule Test_Obfuscation_Pattern {
    meta:
        description = "Simulated code obfuscation indicators"
        author = "REACHABLE Security"
        severity = "test"
        
    strings:
        // Base64 encoded test markers
        $b64_test = "VEVTVC1NQUxXQVJFLVNJR05BVFVSRS0xMjM0NQ==" // TEST-MALWARE-SIGNATURE-12345
        $b64_beacon = "UkVBQ0hBQkxFX1RFU1RfQkVBQ09OOjpDMl9DQUxMQkFDSw==" // REACHABLE_TEST_BEACON::C2_CALLBACK
        
        // Hex encoded markers
        $hex_test = "544553542d4d414c574152452d5349474e41545552452d3132333435"
        
    condition:
        any of them
}

rule Synthetic_Bad_Hash_Reference {
    meta:
        description = "Reference to known-bad test hashes"
        author = "REACHABLE Security"
        severity = "test"
        
    strings:
        $deadbeef = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        $cafebabe = "cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe"
        $eicar_md5 = "44d88612fea8a8f36de82e1278abb02f"
        $eicar_sha1 = "3395856ce81f2b7382dee72602f798b642f14140"
        
    condition:
        any of them
}
