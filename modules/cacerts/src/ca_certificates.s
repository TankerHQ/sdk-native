.global embedded_cacerts_data, embedded_cacerts_size, _embedded_cacerts_data, _embedded_cacerts_size

embedded_cacerts_data:
_embedded_cacerts_data:
.incbin "../data/cacert.pem"
embedded_cacerts_data_end:

.align 4
embedded_cacerts_size:
_embedded_cacerts_size:
.int embedded_cacerts_data_end-embedded_cacerts_data
