rule Rubeus_Detection {
    meta:
        description = "Detects Rubeus Kerberos interaction tool"
        author = "SentinelX"
        date = "2026-02-23"
    strings:
        $s1 = "Rubeus.exe" ascii wide nocase
        $s2 = "asktgt" ascii wide nocase
        $s3 = "s4u" ascii wide nocase
        $s4 = "ptt" ascii wide nocase
        $s5 = "kerberoast" ascii wide nocase
        $s6 = "asreproast" ascii wide nocase
        $s7 = "tgtdeleg" ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and 4 of ($s*)
}
