_nsdiff() {
    local cur="${COMP_WORDS[COMP_CWORD]}" prev="${COMP_WORDS[COMP_CWORD-1]}"
    case "$prev" in
        --section) COMPREPLY=( $(compgen -W "namespaces credentials limits cgroup network mounts environment security all" -- "$cur") ) ;;
        --snapshot-format) COMPREPLY=( $(compgen -W "native portable" -- "$cur") ) ;;
        *)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "--help --version --json --only-differences --explain --summary --quiet --section --capture --against --snapshots --snapshot-info --verify-snapshot --snapshot-compat --snapshot-id --semantic-id --snapshot-manifest --snapshot-schema --export-snapshot-json --convert-snapshot --snapshot-format" -- "$cur") )
            else
                mapfile -t COMPREPLY < <(compgen -f -- "$cur")
            fi ;;
    esac
}
complete -F _nsdiff nsdiff
