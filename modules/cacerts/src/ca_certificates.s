.global embedded_cacerts_data, _embedded_cacerts_data, embedded_cacerts_size, _embedded_cacerts_size

.balign 4
embedded_cacerts_data:
_embedded_cacerts_data:
.incbin "../data/cacert.pem"

.balign 4, 32
embedded_cacerts_size:
_embedded_cacerts_size:
.int embedded_cacerts_size-embedded_cacerts_data
