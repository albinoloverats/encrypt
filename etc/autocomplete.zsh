#compdef encrypt decrypt

local args ciphers hashes modes state

args=(
	'(-h --help)'{-h,--help}'[Display this message]'
	'(-l --licence)'{-l,--licence}'[Display GNU GPL v3 licence header]'
	'(-v --version)'{-v,--version}'[Display application version]'
	'(-k --key)'{-k,--key=}'[File whose data will be used to generate the key]:Key:_files'
	'(-p --password)'{-p,--password=}'[Password used to generate the key]:Password:'
	'(-r --raw)'{-r,--raw}'[Don’t generate or look for an encrypt header; this IS NOT recommended, but can be usefull in some (limited) situations.]'
)

if [[ $service = encrypt ]]
then
	args+=(
		'(-c --cipher)'{-c,--cipher=}'[Algorithm to use to encrypt data]: :->ciphers'
		'(-s --hash)'{-s,--hash=}'[Hash algorithm to generate key]: :->hashes'
		'(-m --mode)'{-s,--hash=}'[The encryption mode to use]: :->mdoes'
		'(-x --no-compress)'{-x,--no-compress}'[Do not compress the plaintext using the xz algorithm]'
		'(-f --follow)'{-f,--follow}'[Follow symlinks, the default is to store the link itself]'
		'(-b --back-compat)'{-b,--back-compat}'[Create an encrypted file that is backwards compatible]'
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

	modes)
		compadd list ${=${(f)"$($service -m list 2>&1 | tr '[A-Z]' '[a-z]')"}:#*\:}
		;;
esac
