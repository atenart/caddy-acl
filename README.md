# *Caddy ACL*

Access Control Lists middleware for [Caddy](https://caddyserver.com). Allows to
limit access of locations to certain client addresses.

## Syntax

	acl paths... {
		allow	<subnet|ip>
		deny	<subnet|ip>
		status	<code>
		header	<name>
	}

  - **paths...**: list of space separated locations to which apply ACL rules.
  - **allow**: *subnet* or IP to explicitly allow to access *paths*.
  - **block**: *subnet* or IP to explicitly deny from accessing *paths*.
  - **status**: respond with the given *code* when denying a request. Defaults to
    403.
  - **header**: use the given *header* to get the client IP address. It always
    looks for *X-Forwarded-For*.

Denied subnets and IPs are checked first. If *allow* is used, only subnets and
addresses explicitly allowed will be accepted. Otherwise only addresses
explicitly denied will be rejected. Two options only make sense when *deny* is
used: *header* and *status*. Multiple *acl* blocks can be used.

## Examples

Only allow a given subnet (*192.168.42.0/24*) to access all files in */private*:

	acl /private {
		allow 192.168.42.0/24
	}

Allow *192.168.42.0/24* to access to */private* and */kikoo*, but deny access to
*192.168.42.15*:

	acl /private /kikoo {
		allow 192.168.42.0/24
		deny 192.168.42.15
	}

Deny only 2 subnets and one address from accessing */private*:

	acl /private {
		deny 192.168.42.0/24
		deny 10.10.52.0/27
		deny 192.168.0.2
	}
