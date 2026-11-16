# @TEST-DOC: The analyzers are attached by content, not by port: no SLMP violations for HTTP on 5000/tcp or RTP on 5004/udp, and SLMP on 6000/tcp and 6001/udp is found.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/slmp_not_slmp.pcap ${PACKAGE} %INPUT >output
# @TEST-EXEC: zeek-cut id.resp_p proto service < conn.log | sort >>output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff slmp.log

event analyzer_violation_info(atype: AllAnalyzers::Tag, info: AnalyzerViolationInfo)
	{
	local reason = sub(info$reason, / \(\/.*\)$/, "");
	print fmt("violation %s %s %s", atype, info$c$id$resp_p, reason);
	}
