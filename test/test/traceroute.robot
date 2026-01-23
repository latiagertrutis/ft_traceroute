*** Settings ***
Library     Process
Library     String


*** Variables ***
${TRACEROUTE_BIN}       /traceroute
${MY_TRACEROUTE_BIN}    /ft_traceroute_dir/ft_traceroute


*** Test Cases ***
Test working IP
    [Documentation]    Test with working ip
    [Timeout]               30s

    ${result}=              Run Process             ${TRACEROUTE_BIN}       8.8.8.8
    Log                     ${result.stdout}
    ${my_result}=           Run Process             ${MY_TRACEROUTE_BIN}    8.8.8.8
    Log                     ${my_result.stdout}

    ${first_line}=          Get Line                ${result.stdout}        0
    ${my_first_line}=       Get Line                ${my_result.stdout}     0
    ${my_first_line}=       Replace String          ${my_first_line}        ft_traceroute           traceroute
    Should Be Equal         ${first_line}           ${my_first_line}
    Should Be Equal         ${result.rc}            ${my_result.rc}

Test working IP icmp
    [Documentation]    Test with working ip with icmp protocol
    [Timeout]               30s

    ${result}=              Run Process             ${TRACEROUTE_BIN}       -I                      8.8.8.8
    Log                     ${result.stdout}
    ${my_result}=           Run Process             ${MY_TRACEROUTE_BIN}    -i                      8.8.8.8
    Log                     ${my_result.stdout}

    ${first_line}=          Get Line                ${result.stdout}        0
    ${my_first_line}=       Get Line                ${my_result.stdout}     0
    ${my_first_line}=       Replace String          ${my_first_line}        ft_traceroute           traceroute
    Should Be Equal         ${first_line}           ${my_first_line}
    Should Be Equal         ${result.rc}            ${my_result.rc}

Test working IP with correct packet lenght
    [Documentation]    Test with working ip with correct packet lenght
    [Timeout]               30s

    ${result}=              Run Process             ${TRACEROUTE_BIN}       8.8.8.8                 4242
    Log                     ${result.stdout}
    ${my_result}=           Run Process             ${MY_TRACEROUTE_BIN}    8.8.8.8                 4242
    Log                     ${my_result.stdout}

    ${first_line}=          Get Line                ${result.stdout}        0
    ${my_first_line}=       Get Line                ${my_result.stdout}     0
    ${my_first_line}=       Replace String          ${my_first_line}        ft_traceroute           traceroute
    Should Be Equal         ${first_line}           ${my_first_line}
    Should Be Equal         ${result.rc}            ${my_result.rc}

Test working IP with incorrect packet lenght
    [Documentation]    Test with working ip with incorrect packet lenght
    [Timeout]               30s

    ${result}=              Run Process             ${TRACEROUTE_BIN}       8.8.8.8                 4
    Log                     ${result.stdout}
    ${my_result}=           Run Process             ${MY_TRACEROUTE_BIN}    8.8.8.8                 4
    Log                     ${my_result.stdout}

    ${first_line}=          Get Line                ${result.stdout}        0
    ${my_first_line}=       Get Line                ${my_result.stdout}     0
    ${my_first_line}=       Replace String          ${my_first_line}        ft_traceroute           traceroute
    Should Be Equal         ${first_line}           ${my_first_line}
    Should Be Equal         ${result.rc}            ${my_result.rc}

Test wrong IP
    [Documentation]    Test with wrong ip
    [Timeout]               30s

    ${result}=              Run Process             ${TRACEROUTE_BIN}       8.8.256.8
    Log                     ${result.stdout}
    ${my_result}=           Run Process             ${MY_TRACEROUTE_BIN}    8.8.256.8
    Log                     ${my_result.stdout}

    Should Be Equal         ${result.rc}            ${my_result.rc}
