# @TEST-DOC: 4E and station number extension frames over UDP: serial number pairing with out-of-order responses and a request without a response.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/slmp_4e_udp.pcap ${PACKAGE} %INPUT >output
# @TEST-EXEC: zeek-cut service < conn.log >>output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff slmp.log
