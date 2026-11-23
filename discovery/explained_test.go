package discovery

import "testing"

// Evidence of DNS, comment and URL signals must mark the tokens the tokenizer
// derives from the same record, comment or URL as explained; otherwise the
// miner reports suppliers that rules already detect.
func TestExplainedSetDNSCommentURL(t *testing.T) {
	page := []Token{
		tok(TDNS, "mx:protection.outlook.com"),
		tok(TDNS, "spf-include:spf.protection.outlook.com"),
		tok(TDNS, "spf-include:_spf.mailer.example"),
		tok(TDNS, "spf-include:spf.single.example"),
		tok(TDNS, "ns:transip.net"),
		tok(TComment, "powered by ccv shop www.ccvshop.nl"),
		tok(TPath, "/typo#conf/ext/"),
		tok(TFile, "app.js"),
		tok(TPath, "/other/dir/"),
	}
	ev := [][4]string{
		{"dns", "MX", "10 example-nl.mail.protection.outlook.com", "microsoft-365"},
		{"dns", "TXT", "v=spf1 include:spf.protection.outlook.com include:_spf.mailer.example -all", "microsoft-365"},
		{"dns", "TXT", "v=spf1 include:spf.single.example ~all", "single"},
		{"dns", "NS", "ns1.transip.net", "transip"},
		{"comment", "", " Powered by CCV Shop www.ccvshop.nl generated ", "ccv-shop"},
		{"resource_url", "", "https://www.example.nl/typo3conf/ext/x/app.js?v=1", "typo3"},
	}
	exp := ExplainedSet("example.nl", page, ev)
	want := map[Token]bool{
		tok(TDNS, "mx:protection.outlook.com"):              true,
		tok(TDNS, "spf-include:spf.protection.outlook.com"): false, // multi-include record: which matched is unknown
		tok(TDNS, "spf-include:_spf.mailer.example"):        false,
		tok(TDNS, "spf-include:spf.single.example"):         true,
		tok(TDNS, "ns:transip.net"):                         true,
		tok(TComment, "powered by ccv shop www.ccvshop.nl"): true,
		tok(TPath, "/typo#conf/ext/"):                       true,
		tok(TFile, "app.js"):                                true,
		tok(TPath, "/other/dir/"):                           false,
	}
	for tk, w := range want {
		if exp[tk] != w {
			typ, v := tk.Split()
			t.Errorf("%s:%s explained=%v, want %v", typ, v, exp[tk], w)
		}
	}
}
