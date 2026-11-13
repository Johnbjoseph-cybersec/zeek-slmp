# @TEST-DOC: Check that the SLMP TCP and UDP analyzers are available.
#
# @TEST-EXEC: zeek -NN | grep -Eqi 'ANALYZER_SLMP_TCP'
# @TEST-EXEC: zeek -NN | grep -Eqi 'ANALYZER_SLMP_UDP'
