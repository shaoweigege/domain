package domain

import (
	"bufio"
	"bytes"
	"errors"
	"net"
	"regexp"
	"strings"

	"golang.org/x/net/publicsuffix"
)

var (
	reDomain = regexp.MustCompile(`^([a-zA-Z0-9]-?)+([a-zA-z0-9])\.[a-zA-Z]{2,4}|\.[a-zA-Z]{2,4}$`)
	//
	ErrBadSyntax         = errors.New("Invalid domain syntax")
	ErrHasNS             = errors.New("Domain already has NS")
	ErrWhoisNotFound     = errors.New("WHOIS server not found")
	ErrConnectionFailed  = errors.New("TCP connection failure")
	ErrConnectionWrite   = errors.New("Error writting to connection")
	ErrAlreadyRegistered = errors.New("Domain already registered")
)

/*
syntax check domain syntax
*/
func syntax(domain string) bool {
	if len(domain) < 3 || len(domain) > 253 {
		return false
	}
	return reDomain.MatchString(domain)
}

/*
ns check
*/
func ns(domain string) bool {
	nss, err := net.LookupNS(domain)
	if err != nil {
		return false
	}
	if len(nss) == 0 {
		return false
	}
	//
	return true
}

// Dialer
type Dialer func(network, address string) (net.Conn, error)

/*
whois record check
*/
func whois(domain string, d Dialer) (bool, error) {
	// get domain tld
	root, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return false, err
	}

	//convert to domain name, and tld
	i := strings.Index(root, ".")
	tld := root[i+1:]

	// find whois server of tld
	record, ok := TLDs[tld]

	// if not found, return
	if !ok {
		return false, ErrWhoisNotFound
	}

	// address
	address := net.JoinHostPort(record.server, "43")
	conn, err := d("tcp", address)
	if err != nil {
		return false, ErrConnectionFailed
	}
	defer conn.Close()

	var b bytes.Buffer
	b.WriteString(domain)
	b.WriteString("\r\n")
	if _, err := conn.Write(b.Bytes()); err != nil {
		return false, ErrConnectionWrite
	}

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), record.available) {
			return true, nil
		}
	}
	return false, ErrAlreadyRegistered
}
