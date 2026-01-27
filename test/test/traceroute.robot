*** Settings ***
Library     Process
Library     String

*** Variables ***
${TRACEROUTE_BIN}       /traceroute
${MY_TRACEROUTE_BIN}    /ft_traceroute_dir/ft_traceroute

*** Test Cases ***
Test working IP
    [Documentation]    Test with working ip
    [Timeout]               100s

    ${result}=              Run Process             ${TRACEROUTE_BIN}       -U                      8.8.8.8
    Log                     ${result.stdout} ${result.stderr}
    ${my_result}=           Run Process             ${MY_TRACEROUTE_BIN}    8.8.8.8
    Log                     ${my_result.stdout} ${my_result.stderr}

    ${first_line}=          Get Line                ${result.stdout}        0
    ${my_first_line}=       Get Line                ${my_result.stdout}     0
    ${my_first_line}=       Replace String          ${my_first_line}        ft_traceroute           traceroute
    ${my_first_line}=       Remove String Using Regexp                      ${my_first_line}        \\(\\d+\\.\\d+\\.\\d+\\.\\d+\\)
    ${first_line}=          Remove String Using Regexp                      ${first_line}           \\(\\d+\\.\\d+\\.\\d+\\.\\d+\\)
    Should Be Equal         ${first_line}           ${my_first_line}
    Should Be Equal         ${result.rc}            ${my_result.rc}

Test working IP icmp
    [Documentation]    Test with working ip with icmp protocol
    [Timeout]               100s

    ${result}=              Run Process             ${TRACEROUTE_BIN}       8.8.8.8
    Log                     ${result.stdout} ${result.stderr}
    ${my_result}=           Run Process             ${MY_TRACEROUTE_BIN}    -i                      8.8.8.8
    Log                     ${my_result.stdout} ${my_result.stderr}

    ${first_line}=          Get Line                ${result.stdout}        0
    ${my_first_line}=       Get Line                ${my_result.stdout}     0
    ${my_first_line}=       Replace String          ${my_first_line}        ft_traceroute           traceroute
    ${my_first_line}=       Remove String Using Regexp                      ${my_first_line}        \\(\\d+\\.\\d+\\.\\d+\\.\\d+\\)
    ${first_line}=          Remove String Using Regexp                      ${first_line}           \\(\\d+\\.\\d+\\.\\d+\\.\\d+\\)
    Should Be Equal         ${first_line}           ${my_first_line}
    Should Be Equal         ${result.rc}            ${my_result.rc}

Test working IP with domain
    [Documentation]    Test with working ip with domain
    [Timeout]               100s

    ${result}=              Run Process             ${TRACEROUTE_BIN}       -U                      google.com
    Log                     ${result.stdout} ${result.stderr}
    ${my_result}=           Run Process             ${MY_TRACEROUTE_BIN}    google.com
    Log                     ${my_result.stdout} ${my_result.stderr}

    ${first_line}=          Get Line                ${result.stdout}        0
    ${my_first_line}=       Get Line                ${my_result.stdout}     0
    ${my_first_line}=       Replace String          ${my_first_line}        ft_traceroute           traceroute
    ${my_first_line}=       Remove String Using Regexp                      ${my_first_line}        \\(\\d+\\.\\d+\\.\\d+\\.\\d+\\)
    ${first_line}=          Remove String Using Regexp                      ${first_line}           \\(\\d+\\.\\d+\\.\\d+\\.\\d+\\)
    Should Be Equal         ${first_line}           ${my_first_line}
    Should Be Equal         ${result.rc}            ${my_result.rc}

Test working IP with domain and icmp
    [Documentation]    Test with working ip with domain and icmp
    [Timeout]               100s

    ${result}=              Run Process             ${TRACEROUTE_BIN}       google.com
    Log                     ${result.stdout} ${result.stderr}
    ${my_result}=           Run Process             ${MY_TRACEROUTE_BIN}    -i                      google.com
    Log                     ${my_result.stdout} ${my_result.stderr}

    ${first_line}=          Get Line                ${result.stdout}        0
    ${my_first_line}=       Get Line                ${my_result.stdout}     0
    ${my_first_line}=       Replace String          ${my_first_line}        ft_traceroute           traceroute
    ${my_first_line}=       Remove String Using Regexp                      ${my_first_line}        \\(\\d+\\.\\d+\\.\\d+\\.\\d+\\)
    ${first_line}=          Remove String Using Regexp                      ${first_line}           \\(\\d+\\.\\d+\\.\\d+\\.\\d+\\)
    Should Be Equal         ${first_line}           ${my_first_line}
    Should Be Equal         ${result.rc}            ${my_result.rc}

Test working IP with correct packet lenght
    [Documentation]    Test with working ip with correct packet lenght
    [Timeout]               100s

    ${result}=              Run Process             ${TRACEROUTE_BIN}       -U                      8.8.8.8                 4242
    Log                     ${result.stdout} ${result.stderr}
    ${my_result}=           Run Process             ${MY_TRACEROUTE_BIN}    8.8.8.8                 4242
    Log                     ${my_result.stdout} ${my_result.stderr}

    ${first_line}=          Get Line                ${result.stdout}        0
    ${my_first_line}=       Get Line                ${my_result.stdout}     0
    ${my_first_line}=       Replace String          ${my_first_line}        ft_traceroute           traceroute
    ${my_first_line}=       Remove String Using Regexp                      ${my_first_line}        \\(\\d+\\.\\d+\\.\\d+\\.\\d+\\)
    ${first_line}=          Remove String Using Regexp                      ${first_line}           \\(\\d+\\.\\d+\\.\\d+\\.\\d+\\)
    Should Be Equal         ${first_line}           ${my_first_line}
    Should Be Equal         ${result.rc}            ${my_result.rc}

Test working IP with no DNS resolution
    [Documentation]    Test with working ip with incorrect packet lenght
    [Timeout]               100s

    ${result}=              Run Process             ${TRACEROUTE_BIN}       -U                      -n                      google.com
    Log                     ${result.stdout} ${result.stderr}
    ${my_result}=           Run Process             ${MY_TRACEROUTE_BIN}    -n                      google.com
    Log                     ${my_result.stdout} ${my_result.stderr}

    ${first_line}=          Get Line                ${result.stdout}        0
    ${my_first_line}=       Get Line                ${my_result.stdout}     0
    ${my_first_line}=       Replace String          ${my_first_line}        ft_traceroute           traceroute
    ${my_first_line}=       Remove String Using Regexp                      ${my_first_line}        \\(\\d+\\.\\d+\\.\\d+\\.\\d+\\)
    ${first_line}=          Remove String Using Regexp                      ${first_line}           \\(\\d+\\.\\d+\\.\\d+\\.\\d+\\)
    Should Be Equal         ${first_line}           ${my_first_line}
    Should Be Equal         ${result.rc}            ${my_result.rc}

Test working IP with too big packet lenght
    [Documentation]    Test with working ip with packet lenght too big
    [Timeout]               100s

    ${result}=              Run Process             ${TRACEROUTE_BIN}       -U                      8.8.8.8                 9999999999999999999999999999
    Log                     ${result.stdout} ${result.stderr}
    ${my_result}=           Run Process             ${MY_TRACEROUTE_BIN}    8.8.8.8                 9999999999999999999999999999
    Log                     ${my_result.stdout} ${my_result.stderr}

    ${first_line}=          Get Line                ${result.stdout}        0
    ${my_first_line}=       Get Line                ${my_result.stdout}     0
    ${my_first_line}=       Replace String          ${my_first_line}        ft_traceroute           traceroute
    ${my_first_line}=       Remove String Using Regexp                      ${my_first_line}        \\(\\d+\\.\\d+\\.\\d+\\.\\d+\\)
    ${first_line}=          Remove String Using Regexp                      ${first_line}           \\(\\d+\\.\\d+\\.\\d+\\.\\d+\\)
    Should Be Equal         ${first_line}           ${my_first_line}
    Should Be Equal         ${result.rc}            ${my_result.rc}

Test working IP with incorrect packet lenght
    [Documentation]    Test with working ip with incorrect packet lenght
    [Timeout]               100s

    ${result}=              Run Process             ${TRACEROUTE_BIN}       -U                      8.8.8.8                 4
    Log                     ${result.stdout} ${result.stderr}
    ${my_result}=           Run Process             ${MY_TRACEROUTE_BIN}    8.8.8.8                 4
    Log                     ${my_result.stdout} ${my_result.stderr}

    ${first_line}=          Get Line                ${result.stdout}        0
    ${my_first_line}=       Get Line                ${my_result.stdout}     0
    ${my_first_line}=       Replace String          ${my_first_line}        ft_traceroute           traceroute
    ${my_first_line}=       Remove String Using Regexp                      ${my_first_line}        \\(\\d+\\.\\d+\\.\\d+\\.\\d+\\)
    ${first_line}=          Remove String Using Regexp                      ${first_line}           \\(\\d+\\.\\d+\\.\\d+\\.\\d+\\)
    Should Be Equal         ${first_line}           ${my_first_line}
    Should Be Equal         ${result.rc}            ${my_result.rc}

Test working IP low hops
    [Timeout]               100s

    ${result}=              Run Process             ${TRACEROUTE_BIN}       -U                      -m 2                    8.8.8.8
    Log                     ${result.stdout} ${result.stderr}
    ${my_result}=           Run Process             ${MY_TRACEROUTE_BIN}    -m 2                    8.8.8.8
    Log                     ${my_result.stdout} ${my_result.stderr}

    ${first_line}=          Get Line                ${result.stdout}        0
    ${my_first_line}=       Get Line                ${my_result.stdout}     0
    ${my_first_line}=       Replace String          ${my_first_line}        ft_traceroute           traceroute
    ${my_first_line}=       Remove String Using Regexp                      ${my_first_line}        \\(\\d+\\.\\d+\\.\\d+\\.\\d+\\)
    ${first_line}=          Remove String Using Regexp                      ${first_line}           \\(\\d+\\.\\d+\\.\\d+\\.\\d+\\)
    Should Be Equal         ${first_line}           ${my_first_line}
    Should Be Equal         ${result.rc}            ${my_result.rc}

    
Test working IP first ttl too high
    [Timeout]               100s

    ${result}=              Run Process             ${TRACEROUTE_BIN}       -U                      -m 100                  -f 95                   8.8.8.8
    Log                     ${result.stdout} ${result.stderr}
    ${my_result}=           Run Process             ${MY_TRACEROUTE_BIN}    -m 100                  -f 95                   8.8.8.8
    Log                     ${my_result.stdout} ${my_result.stderr}

    ${my_output}=           Replace String          ${my_result.stdout}     ft_traceroute           traceroute
    Should Be Equal         ${result.stdout}        ${my_output}
    Should Be Equal         ${result.rc}            ${my_result.rc}
    
Test wrong IP
    [Documentation]    Test with wrong ip
    [Timeout]               100s

    ${result}=              Run Process             ${TRACEROUTE_BIN}       -U                      8.8.256.8
    Log                     ${result.stdout} ${result.stderr}
    ${my_result}=           Run Process             ${MY_TRACEROUTE_BIN}    8.8.256.8
    Log                     ${my_result.stdout} ${my_result.stderr}

    Should Be Equal         ${result.rc}            ${my_result.rc}

Test wrong greater first than hops
    [Timeout]               100s

    ${result}=              Run Process             ${TRACEROUTE_BIN}       -U                      -m 1                    -f 3                    8.8.8.8
    Log                     ${result.stdout} ${result.stderr}
    ${my_result}=           Run Process             ${MY_TRACEROUTE_BIN}    -m 1                    -f 3                    8.8.8.8
    Log                     ${my_result.stdout} ${my_result.stderr}

    Should Not Be Equal     ${result.rc}            ${0}
    Should Not Be Equal     ${my_result.rc}         ${0}


Test only one query per hop
    [Timeout]               100s

    ${result}=              Run Process             ${TRACEROUTE_BIN}       -U                      -q 1                    8.8.8.8
    Log                     ${result.stdout} ${result.stderr}
    ${my_result}=           Run Process             ${MY_TRACEROUTE_BIN}    -q 1                    8.8.8.8
    Log                     ${my_result.stdout} ${my_result.stderr}

    ${first_line}=          Get Line                ${result.stdout}        0
    ${my_first_line}=       Get Line                ${my_result.stdout}     0
    ${my_first_line}=       Replace String          ${my_first_line}        ft_traceroute           traceroute
    ${my_first_line}=       Remove String Using Regexp                      ${my_first_line}        \\(\\d+\\.\\d+\\.\\d+\\.\\d+\\)
    ${first_line}=          Remove String Using Regexp                      ${first_line}           \\(\\d+\\.\\d+\\.\\d+\\.\\d+\\)
    Should Be Equal         ${first_line}           ${my_first_line}
    Should Be Equal         ${result.rc}            ${my_result.rc}

Test negative queries per hop
    [Timeout]               100s

    ${result}=              Run Process             ${TRACEROUTE_BIN}       -U                      -q -42                  8.8.8.8
    Log                     ${result.stdout} ${result.stderr}
    ${my_result}=           Run Process             ${MY_TRACEROUTE_BIN}    -q -42                  8.8.8.8
    Log                     ${my_result.stdout} ${my_result.stderr}

    Should Not Be Equal     ${result.rc}            ${0}
    Should Not Be Equal     ${my_result.rc}         ${0}

Test zero queries per hop
    [Timeout]               100s

    ${result}=              Run Process             ${TRACEROUTE_BIN}       -U                      -q 0                    8.8.8.8
    Log                     ${result.stdout} ${result.stderr}
    ${my_result}=           Run Process             ${MY_TRACEROUTE_BIN}    -q 0                    8.8.8.8
    Log                     ${my_result.stdout} ${my_result.stderr}

    Should Not Be Equal     ${result.rc}            ${0}
    Should Not Be Equal     ${my_result.rc}         ${0}

Test big ammount of queries per hop
    [Timeout]               100s

    ${result}=              Run Process             ${TRACEROUTE_BIN}       -U                      -q 100                  8.8.8.8
    Log                     ${result.stdout} ${result.stderr}
    ${my_result}=           Run Process             ${MY_TRACEROUTE_BIN}    -q 100                  8.8.8.8
    Log                     ${my_result.stdout} ${my_result.stderr}

    Should Not Be Equal     ${result.rc}            ${0}
    Should Not Be Equal     ${my_result.rc}         ${0}

Test too high ammount of queries per hop
    [Timeout]               100s

    ${result}=              Run Process             ${TRACEROUTE_BIN}       -U                      -q 999999999999999999999                        8.8.8.8
    Log                     ${result.stdout} ${result.stderr}
    ${my_result}=           Run Process             ${MY_TRACEROUTE_BIN}    -q 999999999999999999999                        8.8.8.8
    Log                     ${my_result.stdout} ${my_result.stderr}

    Should Not Be Equal     ${result.rc}            ${0}
    Should Not Be Equal     ${my_result.rc}         ${0}
