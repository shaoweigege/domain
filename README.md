## domain
domain name availability check using WHOIS protocol.

## Usage
1. install:
`
go get github.com/superiss/domain
`

## Example
```go
func main() {
	// using default dialer
	d := net.Dialer{Timeout: 30 * time.Second}

	// // using socks5 dialer
	// d, err := proxy.SOCKS5("tcp", "118.70.179.208:1080", nil, proxy.Direct)
	// if err != nil {
	// 	fmt.Println(err)
	// 	return
	// }

	status, err := domain.AvailableCheck("sendizosdfs.com", d.Dial)
	fmt.Println(status, err)

	fmt.Println("done")
}
```

## How it works?
The first thing to check is if the domain has a valid syntax.
a valid domain name is an alphanumeric string with hyphens (-), below condition must apply:
    - starts/end with number or letter.
    - no consecutive hyphen.

Then, NS Check, assuming all available domains have no Nameserver DNS (NS record).

Last, if the above conditions are passed, check whois DNS by dialing the corresponded WHOIS server, if the domain has no records in the WHOIS database then we assume the domain is available.

## WHOIS server
Big thanks to @neonbunny
`
https://github.com/nccgroup/typofinder/blob/master/TypoMagic/datasources/whois-servers.txt
`