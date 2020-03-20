.global embedded_cacerts_data, _embedded_cacerts_data, embedded_cacerts_size, _embedded_cacerts_size

.balign 4
embedded_cacerts_data:
_embedded_cacerts_data:
.incbin "../data/cacert.pem"

# AppleClang for ARM thinks this is a function, and so gives a spurious warnings if we do not align it to 4 bytes
# It is nontrivial to portably mark labels as data and not code, so just pad the PEM file with spaces (32d = 20h = ' ')
.balign 4, 32
embedded_cacerts_size:
_embedded_cacerts_size:
.int embedded_cacerts_size-embedded_cacerts_data
