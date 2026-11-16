# @TEST-DOC: Malformed frames (unknown subheader, non-zero fixed field, length beyond the datagram) raise protocol violations; the valid pair before them is still logged.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/slmp_malformed.pcap ${PACKAGE} %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff slmp.log

# The UDP cases are requests without a response, which the DPD signatures
# do not match; attach the analyzer to their ports explicitly.
redef SLMP::ports_udp += { 5003/udp, 5004/udp };

event analyzer_violation_info(atype: AllAnalyzers::Tag, info: AnalyzerViolationInfo)
	{
	# Drop the source location suffix, which contains a local build path.
	local reason = sub(info$reason, / \(\/.*\)$/, "");
	print fmt("violation %s %s %s", atype, info$c$id$resp_p, reason);
	}
