#compdef zrex

_zrex() {
  local candidate
  local -a candidates
  while IFS= read -r candidate; do
    [[ -n $candidate ]] && candidates+=("$candidate")
  done < <("${words[1]}" __complete "${words[CURRENT]}" "${(@)words[2,CURRENT-1]}" 2>/dev/null)
  compadd -M 'm:{a-zA-Z}={A-Za-z}' -- "${candidates[@]}"
}

if [[ "${funcstack[1]-}" == "_zrex" ]]; then
  _zrex "$@"
else
  compdef _zrex zrex
fi
