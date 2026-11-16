# Dynamic protocol detection for SLMP binary frames.
#
# The client side matches a request subheader: 3E (50H 00H), or 4E/station
# number extension (54H 00H / 68H 00H) followed by a 2-byte serial number
# and the fixed 00H 00H. The server side matches the response subheaders
# (D0H, D4H, E8H) and requires the client match in the other direction, so
# the analyzer is attached only when both sides look like SLMP.

signature dpd_slmp_tcp_client {
  ip-proto == tcp
  payload /^(\x50\x00|\x54\x00[\x00-\xff]{2}\x00\x00|\x68\x00[\x00-\xff]{2}\x00\x00)/
}

signature dpd_slmp_tcp_server {
  ip-proto == tcp
  payload /^(\xd0\x00|\xd4\x00[\x00-\xff]{2}\x00\x00|\xe8\x00[\x00-\xff]{2}\x00\x00)/
  requires-reverse-signature dpd_slmp_tcp_client
  enable "SLMP_TCP"
}

signature dpd_slmp_udp_client {
  ip-proto == udp
  payload /^(\x50\x00|\x54\x00[\x00-\xff]{2}\x00\x00|\x68\x00[\x00-\xff]{2}\x00\x00)/
}

signature dpd_slmp_udp_server {
  ip-proto == udp
  payload /^(\xd0\x00|\xd4\x00[\x00-\xff]{2}\x00\x00|\xe8\x00[\x00-\xff]{2}\x00\x00)/
  requires-reverse-signature dpd_slmp_udp_client
  enable "SLMP_UDP"
}
