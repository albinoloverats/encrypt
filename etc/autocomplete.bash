_encrypt()
{
    local cur prev opts 
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    opts="-h --help -v --version -l --licence \
          -k --key -p --password \
          -q --quiet -d --debug"

    [ "$1" == "encrypt" ] && opts="$opts -c --cipher -s --hash -x --no-compress"

    if [[ "${cur}" == -* ]]
    then
        COMPREPLY=($(compgen -W "${opts}" -- "${cur}"))
    else
        case "${prev}" in
            -h|--help|-v|--version|-l|--licence)
                ;;
            -k|--key)
                COMPREPLY=($(compgen -A file -- "${cur}"))
                ;;
            -d|--debug)
                COMPREPLY=($(compgen -W "everything verbose debug info warning error fatal" -- "${cur}"))
                ;;
            -c|--cipher)
                COMPREPLY=($(compgen -W "list $(encrypt -c list 2>&1 | tr '[A-Z]' '[a-z]')" -- "${cur}"))
                ;;
            -s|--hash)
                COMPREPLY=($(compgen -W "list $(encrypt -s list 2>&1 | tr '[A-Z]' '[a-z]')" -- "${cur}"))
                ;;
            -p|--password|-x|--no-compress)
                ;;
            *)
                COMPREPLY=($(compgen -A file -- "${cur}"))
                ;;
        esac
    fi

    return 0
}

complete -F _encrypt encrypt decrypt
