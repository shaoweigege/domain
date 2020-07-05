package domain

/*
AvailableCheck func
*/
func AvailableCheck(domain string, d Dialer) (bool, error) {
	if !syntax(domain) {
		return false, ErrBadSyntax
	}
	// check domain already have NS record
	if ns(domain) {
		return false, ErrHasNS
	}
	// whois check
	return whois(domain, d)
}
