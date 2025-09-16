<?php
/**
 * FreePBX Click-to-Call PHP Script
 * Adapted from Alisson Pelizaro's version: https://github.com/alissonpelizaro/Asterisk-Click-to-Call
 * Provides input validation, JSON results, and improved readability.
 * Provides pjsip support and error handling.
 * This script is intended to be used with FreePBX and Asterisk for click-to-call functionality.
 */

// Configuration settings
$config = [
	'host' => '127.0.0.1',
	'port' => 5038, // Default AMI port
    'user' => 'admin', // AMI username
    'secret' => 'MYSECRETPASS', // AMI password
	'callerIdTemplate' => 'CTR Plugin (%s)',
	'context' => 'from-internal',
	'waitTime' => 30,
	'priority' => 1,
	'maxRetry' => 2,
	'allowedIPs' => [
		'172.31.0.0/16',     // IPv4 with wildcard
		'2001:db8::/32',   // IPv6 CIDR notation
		'::1',             // IPv6 localhost
		'127.0.0.1'        // IPv4 localhost

	],
];

// Retrieve and sanitize request parameters
$extension = isset($_REQUEST['exten']) ? trim($_REQUEST['exten']) : '';
$number = isset($_REQUEST['number']) ? trim(strtolower($_REQUEST['number'])) : '';

// Initialize result array
$result = [
	'Success' => true,
	'ValidInput' => true,
	'Description' => '',
	'Technology' => '',
	'OriginateResponse' => '',
];

// Validate input parameters
if (!preg_match('/^\\+?[0-9]+$/', $number)) {
	$result = setError($result, "Invalid number format: %s", $number);
}

if (!preg_match('/^[0-9]+$/', $extension)) {
	$result = setError($result, "Invalid extension format: %s", $extension);
}

function ipMatchesPattern($ip, $pattern)
{
	if (strpos($pattern, '*') !== false)
	{
		$pattern = str_replace('*', '.*', $pattern);

		return preg_match('/^' . $pattern . '$/', $ip);
	}
	if (strpos($pattern, '/') !== false)
	{
		list($subnet, $bits) = explode('/', $pattern, 2);

		$ipBin     = @inet_pton($ip);
		$subnetBin = @inet_pton($subnet);

		if ($ipBin === false || $subnetBin === false || !is_numeric($bits))
		{
			return false;
		}

		$bits = (int) $bits;
		$lenBytes = strlen($subnetBin);           // 4 voor IPv4, 16 voor IPv6
		$maxBits  = $lenBytes * 8;

		// Ongeldige prefixlengte
		if ($bits < 0 || $bits > $maxBits)
		{
			return false;
		}

		// Bouw een binaire mask op basis van bits
		$fullBytes     = intdiv($bits, 8);
		$remainingBits = $bits % 8;

		$mask = str_repeat("\xff", $fullBytes);

		if ($remainingBits > 0)
		{
			$mask .= chr(0xff << (8 - $remainingBits));
		}

		// Vul aan tot de juiste lengte met null-bytes
		$mask .= str_repeat("\x00", $lenBytes - strlen($mask));

		// Vergelijk met bitwise AND
		return (($ipBin & $mask) === ($subnetBin & $mask));
	}

	return $ip === $pattern;
}

// Check if request is from an allowed IP address
if ($result['Success'])
{
	$clientIP = $_SERVER["REMOTE_ADDR"];
	$allowed  = false;
	foreach ($config['allowedIPs'] as $pattern)
	{
		if (ipMatchesPattern($clientIP, $pattern))
		{
			$allowed = true;
			break;
		}
	}
	if (!$allowed)
	{
		$result = setError($result, "Unauthorized IP address: %s", $clientIP);
	}
}


// Establish socket connection and authenticate
if ($result['Success']) {
	$socket = stream_socket_client("tcp://{$config['host']}:{$config['port']}", $errno, $errstr);

	if (!$socket) {
		$result = setError($result, "Socket connection failed: %s (%s)", $errstr, $errno);
	} else {
		$authRequest = "Action: Login\r\nUsername: {$config['user']}\r\nSecret: {$config['secret']}\r\nEvents: off\r\n\r\n";
		fwrite($socket, $authRequest);
		usleep(200000);
		$authResponse = fread($socket, 4096);

		if (strpos($authResponse, 'Success') === false) {
			$result = setError($result, "Authentication failed");
		} else {
			// Fetch technology from Asterisk extension database
			$dbGetRequest = "Action: DBGet\r\nFamily: DEVICE\r\nKey: $extension/tech\r\n\r\n";
			fwrite($socket, $dbGetRequest);
			usleep(200000);
			$dbGetResponse = fread($socket, 4096);

			if (preg_match('/Val: (\w+)/', $dbGetResponse, $matches)) {
				$tech = strtoupper($matches[1]);
				$result['Technology'] = $tech; // Add technology to result JSON
			} else {
				$result = setError($result, "Failed to retrieve technology for extension: %s", $extension);
			}

			if ($result['Success']) {
				// Originate call with retrieved technology
				$originateRequest = "Action: Originate\r\nChannel: $tech/$extension\r\nWaitTime: {$config['waitTime']}\r\nCallerId: " . sprintf($config['callerIdTemplate'], $number) . "\r\nExten: $number\r\nContext: {$config['context']}\r\nPriority: {$config['priority']}\r\nAsync: yes\r\n\r\n";
				fwrite($socket, $originateRequest);
				usleep(200000);
				$originateResponse = fread($socket, 4096);
				$result['OriginateResponse'] = $originateResponse;

				if (strpos($originateResponse, 'Success') !== false) {
					$result['Description'] = "Extension $extension is calling $number.";
				} else {
					$result = setError($result, "Call initiation failed");
				}
			}

			// Logoff
			fwrite($socket, "Action: Logoff\r\n\r\n");
		}

		fclose($socket);
	}
}

// Helper function to set error
function setError($result, $message, ...$args) {
	$result['Success'] = false;
	$result['ValidInput'] = false;
	$result['Description'] = vsprintf($message, $args);
	return $result;
}

// Output JSON result
header('Content-Type: application/json');
echo json_encode($result, JSON_PRETTY_PRINT);

?>
