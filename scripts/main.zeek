##! Logging for SLMP (SeamLess Message Protocol), binary 3E, 4E and station
##! number extension frames over TCP and UDP.
##!
##! One slmp.log line is written per request/response pair. Requests and
##! responses are paired by serial number for 4E and station number
##! extension frames, and in order of arrival for 3E frames (which carry no
##! serial number). Requests without a response and responses without a
##! request are logged on their own, with a status saying so.

@load base/protocols/conn/removal-hooks

@load-sigs ./dpd.sig

module SLMP;

export {
	redef enum Log::ID += { LOG };

	global log_policy: Log::PolicyHook;

	## TCP ports the analyzer is always attached to. Empty by default: SLMP
	## has no fixed port, and the analyzer is attached by the signatures in
	## dpd.sig instead. Add a port with redef to attach the analyzer to it
	## unconditionally, for example when only one side of the traffic is
	## captured.
	const ports_tcp: set[port] = {} &redef;

	## UDP ports the analyzer is always attached to. Empty by default, as
	## for ports_tcp.
	const ports_udp: set[port] = {} &redef;

	## Maximum number of requests kept waiting for a response per
	## connection. When exceeded, the oldest is logged as no_response.
	const max_pending = 64 &redef;

	type Info: record {
		## Time of the request, or of the response if no request was seen.
		ts: time &log;
		uid: string &log;
		id: conn_id &log;
		proto: transport_proto &log;
		## "3E", "4E" or "station-ext".
		frame_type: string &log;
		## Serial number (4E and station number extension frames only).
		serial: count &log &optional;
		## Request destination network number.
		network: count &log &optional;
		## Request destination station number.
		station: count &log &optional;
		## Request destination module I/O number (hex).
		module_io: string &log &optional;
		## Request destination multidrop station number.
		multidrop: count &log &optional;
		## Request destination extension station number (station number
		## extension frames only).
		ext_station: count &log &optional;
		## Monitoring timer, in units of 250 ms (0 = wait forever).
		monitoring_timer: count &log &optional;
		## Command name.
		command: string &log &optional;
		## Command code (hex).
		command_code: string &log &optional;
		## Subcommand (hex).
		subcommand: string &log &optional;
		## Device name (for example "D" or "M") for decoded device commands.
		## For random read/write this is the first device of the request.
		device: string &log &optional;
		## Head device number, as sent on the wire (numeric value).
		head_device: count &log &optional;
		## Device and number in the conventional notation, decimal or hex
		## depending on the device (for example "D100" or "X1F").
		address: string &log &optional;
		## Number of points. For random read/write: the number of entries.
		points: count &log &optional;
		## Remote Run mode (hex): 0x0001 forced execution not allowed,
		## 0x0003 forced execution allowed.
		run_mode: string &log &optional;
		## Remote Run clear mode: 0, 1 or 2.
		clear_mode: count &log &optional;
		## Model name from a Read Type Name response.
		model_name: string &log &optional;
		## Model code from a Read Type Name response (hex).
		model_code: string &log &optional;
		## End code (hex). 0x0000 means success.
		end_code: string &log &optional;
		## "ok", "error", "no_response" or "no_request".
		status: string &log &optional;
		## Time between request and response.
		rtt: interval &log &optional;

		## Internal: command code, used to decode the response.
		cmd: count &optional;
	};

	global log_slmp: event(rec: Info);

	## Raised for each request frame.
	global request: event(c: connection, is_orig: bool, subheader: count,
	    serial: count, network: count, station: count, module_io: count,
	    multidrop: count, ext_station: count, monitoring_timer: count,
	    command: count, subcommand: count, has_device: bool,
	    device_code: count, head_device: count, points: count,
	    remote_mode: count, clear_mode: count);

	## Raised for each response frame. ``data`` holds at most the first 18
	## bytes of response data.
	global response: event(c: connection, is_orig: bool, subheader: count,
	    serial: count, network: count, station: count, module_io: count,
	    multidrop: count, ext_station: count, end_code: count,
	    has_command: bool, command: count, subcommand: count, data: string);
}

type State: record {
	## Pending 4E and station number extension requests, by key.
	by_serial: table[count] of Info;
	## Pending 3E requests in arrival order.
	fifo: table[count] of Info;
	head: count &default=0;
	tail: count &default=0;
};

redef record connection += {
	slmp: State &optional;
};

global finalize_slmp: Conn::RemovalHook;

## Device codes whose numbers are written in hexadecimal.
const hex_devices: set[count] = { 0x009C, 0x009D, 0x00A0, 0x00B4, 0x00A1,
    0x00B5, 0x00A2, 0x00A3, 0x00B0 };

event zeek_init() &priority=5
	{
	Log::create_stream(SLMP::LOG, [$columns=Info, $ev=log_slmp,
	    $path="slmp", $policy=log_policy]);
	Analyzer::register_for_ports(Analyzer::ANALYZER_SLMP_TCP, ports_tcp);
	Analyzer::register_for_ports(Analyzer::ANALYZER_SLMP_UDP, ports_udp);
	}

function hex4(v: count): string
	{
	return fmt("0x%04x", v);
	}

function get_state(c: connection): State
	{
	if ( ! c?$slmp )
		{
		c$slmp = State($by_serial=table(), $fifo=table());
		Conn::register_removal_hook(c, finalize_slmp);
		}
	return c$slmp;
	}

## Serial-numbered frames are keyed by frame family and serial number.
function serial_key(subheader: count, serial: count): count
	{
	return (subheader & 0x7F) * 65536 + serial;
	}

function base_info(c: connection, ts: time, subheader: count): Info
	{
	local proto = get_port_transport_proto(c$id$resp_p);
	return Info($ts=ts, $uid=c$uid, $id=c$id, $proto=proto,
	    $frame_type=frame_types[subheader]);
	}

function write_info(info: Info)
	{
	Log::write(SLMP::LOG, info);
	}

function flush_oldest(st: State)
	{
	if ( st$head < st$tail )
		{
		local old = st$fifo[st$head];
		delete st$fifo[st$head];
		++st$head;
		old$status = "no_response";
		write_info(old);
		}
	}

event SLMP::request(c: connection, is_orig: bool, subheader: count,
    serial: count, network: count, station: count, module_io: count,
    multidrop: count, ext_station: count, monitoring_timer: count,
    command: count, subcommand: count, has_device: bool,
    device_code: count, head_device: count, points: count,
    remote_mode: count, clear_mode: count)
	{
	local st = get_state(c);
	local info = base_info(c, network_time(), subheader);

	if ( subheader != 0x50 )
		info$serial = serial;
	if ( subheader == 0x68 )
		info$ext_station = ext_station;

	info$network = network;
	info$station = station;
	info$module_io = hex4(module_io);
	info$multidrop = multidrop;
	info$monitoring_timer = monitoring_timer;
	info$cmd = command;
	info$command = commands[command];
	info$command_code = hex4(command);
	info$subcommand = hex4(subcommand);

	if ( has_device )
		{
		info$device = devices[device_code];
		info$head_device = head_device;
		info$points = points;
		if ( device_code in devices )
			{
			if ( device_code in hex_devices )
				info$address = devices[device_code] + to_upper(fmt("%x", head_device));
			else
				info$address = fmt("%s%d", devices[device_code], head_device);
			}
		}
	else if ( command == 0x0403 || command == 0x1402 )
		info$points = points;

	if ( command == 0x1001 )
		{
		info$run_mode = hex4(remote_mode);
		info$clear_mode = clear_mode;
		}

	if ( subheader == 0x50 )
		{
		if ( st$tail - st$head >= max_pending )
			flush_oldest(st);
		st$fifo[st$tail] = info;
		++st$tail;
		}
	else
		{
		local key = serial_key(subheader, serial);
		if ( key in st$by_serial )
			{
			# Serial number reused before a response: log the old one.
			local prev = st$by_serial[key];
			prev$status = "no_response";
			write_info(prev);
			}
		else if ( |st$by_serial| >= max_pending )
			{
			# Drop an arbitrary pending entry to bound memory.
			for ( k, v in st$by_serial )
				{
				v$status = "no_response";
				write_info(v);
				delete st$by_serial[k];
				break;
				}
			}
		st$by_serial[key] = info;
		}
	}

event SLMP::response(c: connection, is_orig: bool, subheader: count,
    serial: count, network: count, station: count, module_io: count,
    multidrop: count, ext_station: count, end_code: count,
    has_command: bool, command: count, subcommand: count, data: string)
	{
	local st = get_state(c);
	local info: Info;
	local found = F;
	local req_sub = subheader & 0x7F;  # D0 -> 50, D4 -> 54, E8 -> 68

	if ( req_sub == 0x50 )
		{
		if ( st$head < st$tail )
			{
			info = st$fifo[st$head];
			delete st$fifo[st$head];
			++st$head;
			found = T;
			}
		}
	else
		{
		local key = serial_key(subheader, serial);
		if ( key in st$by_serial )
			{
			info = st$by_serial[key];
			delete st$by_serial[key];
			found = T;
			}
		}

	if ( found )
		{
		# The first request on a connection is replayed to the analyzer
		# when the response confirms SLMP, so both carry the response
		# time. Leave rtt unset then rather than log a false zero.
		if ( network_time() > info$ts )
			info$rtt = network_time() - info$ts;
		}
	else
		{
		info = base_info(c, network_time(), subheader);
		if ( req_sub != 0x50 )
			info$serial = serial;
		if ( req_sub == 0x68 )
			info$ext_station = ext_station;
		info$network = network;
		info$station = station;
		info$module_io = hex4(module_io);
		info$multidrop = multidrop;
		if ( has_command )
			{
			info$cmd = command;
			info$command = commands[command];
			info$command_code = hex4(command);
			info$subcommand = hex4(subcommand);
			}
		}

	info$end_code = hex4(end_code);

	if ( ! found )
		info$status = "no_request";
	else if ( end_code == 0 )
		info$status = "ok";
	else
		info$status = "error";

	# Read Type Name: 16-byte model name (ASCII, space padded) and a
	# 2-byte little-endian model code.
	if ( end_code == 0 && info?$cmd && info$cmd == 0x0101 && |data| == 18 )
		{
		local name = sub(data[0:16], / +$/, "");
		info$model_name = name;
		info$model_code = hex4(bytestring_to_count(data[16:18], T));
		}

	write_info(info);
	}

# A gap in either direction of a TCP stream can hide a 3E request or its
# response. 3E frames carry no serial number, so pairing in arrival order
# would then attach every later response to the wrong request. Log the
# pending 3E requests as no_response and start pairing afresh.
event content_gap(c: connection, is_orig: bool, seq: count, length: count)
	{
	if ( ! c?$slmp )
		return;

	local st = c$slmp;

	while ( st$head < st$tail )
		flush_oldest(st);
	}

hook finalize_slmp(c: connection)
	{
	if ( ! c?$slmp )
		return;

	local st = c$slmp;

	while ( st$head < st$tail )
		flush_oldest(st);

	for ( _, v in st$by_serial )
		{
		v$status = "no_response";
		write_info(v);
		}

	st$by_serial = table();
	}
