package zerotier

// Root nodes are long-lived nodes at stable physical addresses that can help locate other nodes.
type Root struct {
	// Identity is this root's address and public key(s).
	Identity Identity `json:"identity"`

	// Locator describes the endpoints where this root may be found.
	Locator  Locator `json:"locator"`

	// URL is an optional URL where the latest Root may be fetched.
	// This is one method of locator update, while in-band mechanisms are the other.
	URL      string `json:"url"`
}
