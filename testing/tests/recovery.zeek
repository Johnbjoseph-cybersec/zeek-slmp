# @TEST-DOC: The analyzer keeps parsing after a capture gap, an error response without the error information block, and junk between frames.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/slmp_recovery.pcap ${PACKAGE} %INPUT >output
# @TEST-EXEC: zeek-cut id.resp_p service < conn.log >>output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff slmp.log

event analyzer_violation_info(atype: AllAnalyzers::Tag, info: AnalyzerViolationInfo)
	{
	local reason = sub(info$reason, / \(\/.*\)$/, "");
	print fmt("violation %s %s %s", atype, info$c$id$resp_p, reason);
	}
