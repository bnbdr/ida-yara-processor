import "pe"

rule testrule {
    strings:
        $a = "muahaha"
    condition:
        $a 
}
