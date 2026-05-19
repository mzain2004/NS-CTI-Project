rule Ransomware_Keywords {
    strings:
        $a = "encrypt"
        $b = "ransom"
        $c = ".locked"
    condition:
        2 of them
}

rule Suspicious_Network {
    strings:
        $a = "InternetOpen"
        $b = "URLDownload"
    condition:
        any of them
}

rule AntiDebug {
    strings:
        $a = "IsDebuggerPresent"
        $b = "CheckRemoteDebugger"
    condition:
        any of them
}

rule UPX_Packed {
    strings:
        $a = "UPX0"
        $b = "UPX!"
    condition:
        any of them
}

rule Mimikatz_Strings {
    strings:
        $a = "mimikatz"
        $b = "sekurlsa"
        $c = "lsadump"
    condition:
        any of them
}