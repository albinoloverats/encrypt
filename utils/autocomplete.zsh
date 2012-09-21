#compdef encrypt decrypt

local args ciphers hashes state

args=(
  '(-h --help)'{-h,--help}'[Display this message]'
  '(-l --licence)'{-l,--licence}'[Display GNU GPL v3 licence header]'
  '(-v --version)'{-v,--version}'[Display application version]'
  '(-d --debug)'{-d,--debug=}'[Turn on debugging (to specified level)]: :->debug'
  '(-q --quiet)'{-q,--quiet}'[Turn off all but serious error messages]'
  '(-k --key)'{-k,--key=}'[File whose data will be used to generate the key]:Key:_files'
  '(-p --password)'{-p,--password=}'[Password used to generate the key]:Password:'
)

if [[ $service = encrypt ]]
then
    args+=(
      '(-c --cipher)'{-c,--cipher=}'[Algorithm to use to encrypt data]: :->ciphers'
      '(-s --hash)'{-s,--hash=}'[Hash algorithm to generate key]: :->hashes'
      '(-x --no-compress)'{-x,--no-compress}'[Do not compress the plaintext using the xz algorithm]'
    )
fi

_arguments -C -s "$args[@]" '*:files:_files'

case $state in
    debug)
        compadd everything verbose debug info warning error fatal
        ;;

    ciphers)
        compadd list ${=${(f)"$($service -c list 2>&1 | tr '[A-Z]' '[a-z]')"}:#*\:}
        ;;

    hashes)
        compadd list ${=${(f)"$($service -s list 2>&1 | tr '[A-Z]' '[a-z]')"}:#*\:}
        ;;
esac
