##! Lookup tables for SLMP command and device code names.
##!
##! Values are taken from the command list (section 5.1) and the device code
##! table (section 5.2) of the SLMP Reference Manual SH(NA)-080956ENG-N.

module SLMP;

export {
	## Command code to command name.
	const commands: table[count] of string = {
		[0x0401] = "Device Read",
		[0x1401] = "Device Write",
		[0x0403] = "Device Read Random",
		[0x1402] = "Device Write Random",
		[0x0801] = "Device Entry Monitor Device",
		[0x0802] = "Device Execute Monitor",
		[0x0406] = "Device Read Block",
		[0x1406] = "Device Write Block",
		[0x041A] = "Label Array Label Read",
		[0x141A] = "Label Array Label Write",
		[0x041C] = "Label Read Random",
		[0x141B] = "Label Write Random",
		[0x0613] = "Memory Read",
		[0x1613] = "Memory Write",
		[0x0601] = "Extend Unit Read",
		[0x1601] = "Extend Unit Write",
		[0x1001] = "Remote Run",
		[0x1002] = "Remote Stop",
		[0x1003] = "Remote Pause",
		[0x1005] = "Remote Latch Clear",
		[0x1006] = "Remote Reset",
		[0x0101] = "Read Type Name",
		[0x1631] = "Remote Password Lock",
		[0x1630] = "Remote Password Unlock",
		[0x1810] = "File Read Directory/File",
		[0x1811] = "File Search Directory/File",
		[0x1820] = "File New File",
		[0x1822] = "File Delete File",
		[0x1824] = "File Copy File",
		[0x1825] = "File Change File State",
		[0x1826] = "File Change File Date",
		[0x1827] = "File Open File",
		[0x1828] = "File Read File",
		[0x1829] = "File Write File",
		[0x182A] = "File Close File",
		[0x0619] = "Self Test",
		[0x1617] = "Clear Error",
		[0x2101] = "Ondemand",
	} &default=function(c: count): string { return fmt("unknown-0x%04x", c); } &redef;

	## Binary device code to device name.
	const devices: table[count] of string = {
		[0x0091] = "SM",
		[0x00A9] = "SD",
		[0x009C] = "X",
		[0x009D] = "Y",
		[0x0090] = "M",
		[0x0092] = "L",
		[0x0093] = "F",
		[0x0094] = "V",
		[0x00A0] = "B",
		[0x00A8] = "D",
		[0x00B4] = "W",
		[0x00C1] = "TS",
		[0x00C0] = "TC",
		[0x00C2] = "TN",
		[0x0051] = "LTS",
		[0x0050] = "LTC",
		[0x0052] = "LTN",
		[0x00C7] = "STS",
		[0x00C6] = "STC",
		[0x00C8] = "STN",
		[0x0059] = "LSTS",
		[0x0058] = "LSTC",
		[0x005A] = "LSTN",
		[0x00C4] = "CS",
		[0x00C3] = "CC",
		[0x00C5] = "CN",
		[0x0055] = "LCS",
		[0x0054] = "LCC",
		[0x0056] = "LCN",
		[0x00A1] = "SB",
		[0x00B5] = "SW",
		[0x0098] = "S",
		[0x00A2] = "DX",
		[0x00A3] = "DY",
		[0x00CC] = "Z",
		[0x0062] = "LZ",
		[0x00AF] = "R",
		[0x00B0] = "ZR",
		[0x002C] = "RD",
	} &default=function(c: count): string { return fmt("unknown-0x%04x", c); } &redef;

	## First subheader byte to frame type name.
	const frame_types: table[count] of string = {
		[0x50] = "3E",
		[0xD0] = "3E",
		[0x54] = "4E",
		[0xD4] = "4E",
		[0x68] = "station-ext",
		[0xE8] = "station-ext",
	} &default=function(c: count): string { return fmt("unknown-0x%02x", c); };
}
