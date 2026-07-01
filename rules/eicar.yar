rule EICAR_Test_File
{
    meta:
        description = "Detects the EICAR antivirus test file marker"
        severity = "high"
        source = "masp-default-rules"

    strings:
        $marker = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" ascii

    condition:
        $marker
}
