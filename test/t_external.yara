// compile using:
// yarac32 t_external.yara t_external.rule -d ext_var=3 -d bool_ext_var=true -d int_ext_var=100 -d string_ext_var=helloworld


rule ExternalVariableExample1
{
    condition:
       ext_var == 10
}

rule ExternalVariableExample2
{
    condition:
       bool_ext_var or filesize < int_ext_var
}

rule ExternalVariableExample3
{
    condition:
        string_ext_var contains "text"
}

rule ExternalVariableExample4
{
    condition:
        string_ext_var matches /[a-z]+/
}

rule ExternalVariableExample5
{
    condition:
        /* case insensitive single-line mode */
        string_ext_var matches /[a-z]+/is
}