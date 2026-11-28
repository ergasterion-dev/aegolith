package detect

import (
	"strings"
	"testing"
	"time"
)

// checkMail asserts that isCRLF, CRLF and ScanText agree on v: flagged by
// all three, or by none.
func checkMail(t *testing.T, want bool, values ...string) {
	t.Helper()
	checkTechnique(t, "AEG-CRLF-001", isCRLF, CRLF, want, values)
}

// afterBreak puts each line after a CR LF.
func afterBreak(lines ...string) []string {
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = "x\r\n" + l
	}
	return out
}

// Every kind of line break, with and without blanks after it, at the start of
// the value and inside it. A line after the command changes nothing.
func TestMailCommandLineBreaks(t *testing.T) {
	const cmd = "MAIL FROM:<a@example.com>"
	checkMail(t, true,
		"x\n"+cmd, "x\r"+cmd, "x\r\n"+cmd, "x\n\r"+cmd, "x\r\n\r\n"+cmd,
		"\r\n"+cmd, "x\r\n "+cmd, "x\n\t \t"+cmd, "x\r\n"+strings.Repeat(" ", 500)+cmd,
		"x\n \n  \n"+cmd, "x\r\n"+cmd+"\r\nDATA", "a\nMAIL FROM: us\nRETR 1\n",
	)
	// Without a line break before it, or after anything but blanks, a command
	// is ordinary text.
	checkMail(t, false,
		cmd, " "+cmd, "send "+cmd, "x\r\nthen "+cmd, "x\r\n> "+cmd, "x\r\n>"+cmd,
		"x\r\n> > "+cmd, "x\r\nC: "+cmd, "x\r\n- "+cmd, "x\r\n* "+cmd, "x\r\n`"+cmd+"`",
		"x\r\n\"RETR 1\"", "x\r\n- RETR 1", "x\r\n1. RETR 1", "x\r\n**TOP 1 2**",
		"x\\r\\n"+cmd, "x\r\n\u00a0RETR 1",
	)
}

// Percent-encoded and twice-encoded line breaks, as a query or form sends
// them.
func TestMailCommandEncoded(t *testing.T) {
	for _, v := range []string{
		"x%0d%0aMAIL%20FROM:%3Ca@example.com%3E",
		"x%0ARCPT%20TO:%3Ca@example.com%3E",
		"x%0DRETR%201",
		"x%0d%0a%20a001%20SELECT%20INBOX",
		"x%0d%0aEHLO%20mail.example.com%0d%0a",
	} {
		if _, ok := CRLF(v); !ok {
			t.Errorf("CRLF(%q) = no hit", v)
		}
		if !containsRule(ScanText(v), "AEG-CRLF-001") || !containsRule(ScanQueryText(v), "AEG-CRLF-001") {
			t.Errorf("scan(%q) misses AEG-CRLF-001", v)
		}
	}
	// One decoding pass only.
	if h, ok := CRLF("x%250aRETR%25201"); ok {
		t.Errorf("twice-encoded: %+v", h)
	}
}

func TestSMTPCommands(t *testing.T) {
	checkMail(t, true, afterBreak(
		"MAIL FROM:<a@example.com>", "MAIL FROM: <a@example.com>", "MAIL FROM:\t  <a@example.com>",
		"MAIL FROM:<>", "MAIL FROM:<", "MAIL FROM:<a@example.com> SIZE=100",
		"RCPT TO:<b@example.com>", "RCPT TO: <b@example.com>", "RCPT TO:b@example.com",
		"RCPT TO: b.c+d@mail.example.org", "RCPT TO:<root>", "RCPT TO:<b@[192.0.2.1]>",
		"RCPT TO:<b@example.com> NOTIFY=NEVER", "RCPT TO: b@example.com was refused",
		"EHLO mail.example.com", "HELO example.org", "EHLO  mail-1.example.com  ", "HELO\texample.org\r\nQUIT",
		"EHLO mail.example.com.", "EHLO localhost", "HELO LOCALHOST", "EHLO 192.0.2.1",
		"EHLO [192.0.2.1]", "EHLO [IPv6:2001:db8::1]", "HELO my_host.example",
		"AUTH PLAIN", "AUTH LOGIN", "AUTH CRAM-MD5", "AUTH XOAUTH2", "AUTH  PLAIN ",
		"AUTH PLAIN AGpvaG4AcGFzcw==", "AUTH LOGIN dXNlcg==\r\nDATA", "AUTH XOAUTH2 dXNlcj0=",
		"AUTH PLAIN =", "AUTH LOGIN am9obg==", "AUTH LOGIN YWRtaW4=", "AUTH PLAIN AGEAcGFz",
	)...)
}

func TestSMTPCommandsClear(t *testing.T) {
	checkMail(t, false, afterBreak(
		"MAIL FROM: the team", "MAIL FROM:", "MAIL FROM: a@example.com", "MAIL FROM <a@example.com>",
		"MAILFROM:<a@example.com>", "MAIL  FROM:<a@example.com>", "Mail From: <a@example.com>",
		"mail from:<a@example.com>", "EMAIL FROM:<a@example.com>",
		"RCPT TO:", "RCPT TO: the team", "RCPT TO: <>", "RCPT TO: <your name here>", "RCPT TO: @example",
		"RCPT TO: me @example.com", "RCPT TO: user@", "RCPT TO: <user@ example.com>", "rcpt to:<b@example.com>",
		"RCPTTO:<b@example.com>",
		"EHLO", "HELO ", "HELO everyone", "HELO WORLD", "HELO there.", "HELO .env", "HELO a..b",
		"EHLO and HELO are SMTP greetings", "EHLO mail.example.com failed with a timeout",
		"HELO example.com, then nothing", "HELO [not an address]", "HELO []", "EHLO [192.0.2.1",
		"ehlo mail.example.com", "EHLOS mail.example.com", "HELOmail.example.com", "HELLO example.com",
		"AUTH", "AUTH is required", "AUTH PLAINTEXT", "AUTH GSSAPI", "AUTH PLAIN-TEXT",
		"AUTH LOGIN failed for the admin account", "AUTH LOGIN: disabled", "AUTH PLAIN (disabled)",
		"auth login", "AUTHLOGIN", "AUTHOR LOGIN",
		// One word after the mechanism that is not base64.
		"AUTH LOGIN failed", "AUTH LOGIN FAILED", "AUTH PLAIN rejected", "AUTH LOGIN DISABLED",
		"AUTH PLAIN Rejected.", "AUTH LOGIN error", "AUTH PLAIN abc==x",
		"QUIT", "DATA", "RSET", "NOOP", "VRFY root", "STARTTLS",
	)...)
}

func TestPOP3Commands(t *testing.T) {
	checkMail(t, true, afterBreak(
		"RETR 1", "RETR 12345", "RETR  7  ", "RETR\t2\r\nQUIT", "TOP 1 0", "TOP 10 25", "TOP\t1\t2 \r\nQUIT",
	)...)
	checkMail(t, false, afterBreak(
		"RETR", "RETR one", "RETR 1x", "RETR 1.", "RETR 5 times", "RETR -1", "retr 1", "RETRY 1", "RETR1",
		"TOP", "TOP 10", "TOP 10 reasons", "TOP 5 DISHES", "TOP 10 25 5", "TOP 1 2.5", "TOP 1,2", "TOP,10,20",
		"TOP 10-20", "top 1 2", "TOPS 1 2", "LAPTOP 1 2", "STOP 1 2",
		"USER alice", "PASS secret", "DELE 1", "UIDL", "LIST", "LIST 1", "STAT",
	)...)
}

func TestIMAPCommands(t *testing.T) {
	checkMail(t, true, afterBreak(
		"A001 LOGIN alice secret", `a001 LOGIN "alice" "p w"`, `Z999 LOGIN alice "secret"`,
		"A001 LOGIN {5}", "A001  LOGIN\talice  p@ss\r\nA002 LOGOUT",
		"A001 AUTHENTICATE PLAIN", "A001 AUTHENTICATE CRAM-MD5", "A001 AUTHENTICATE PLAIN AGEAYg==",
		"A001 AUTHENTICATE LOGIN", "A001 AUTHENTICATE XOAUTH2", "A001 AUTHENTICATE OAUTHBEARER",
		"A001 AUTHENTICATE DIGEST-MD5", "A001 AUTHENTICATE GSSAPI", "A001 AUTHENTICATE NTLM",
		"A001 AUTHENTICATE EXTERNAL", "A001 AUTHENTICATE ANONYMOUS", "A001 AUTHENTICATE SCRAM-SHA-1",
		"A001 AUTHENTICATE SCRAM-SHA-256",
		// One argument in upper case is enough for LOGIN.
		"A001 LOGIN ADMIN secret", "A001 LOGIN admin PASS", `A001 LOGIN "ADMIN" "PASS"`, "A001 LOGIN ADMIN P4SS",
		"A001 SELECT INBOX", "A001 SELECT inbox", "A001 SELECT INBOX/Sent", "A001 SELECT INBOX.Drafts",
		`A001 SELECT "Sent Items"`, "A001 SELECT INBOX\r\n",
		"A001 FETCH 1 BODY[]", "A001 FETCH 1:* (FLAGS)", "A001 FETCH 2,4:7 BODY.PEEK[HEADER]",
		"A001 FETCH * ALL", "A001 FETCH 1 RFC822.SIZE", "A001 FETCH 1 FAST", "A001 FETCH 1 FULL",
		"A001 FETCH 1 FLAGS", "A001 FETCH 1 UID", "A001 FETCH 1 ENVELOPE", "A001 FETCH 1 INTERNALDATE",
		"A001 FETCH 1 BODYSTRUCTURE",
		"A001 STORE 1", `A001 STORE 1 +FLAGS (\Deleted)`, `A001 STORE 2:4 -FLAGS.SILENT (\Seen)`,
		"A001 STORE * FLAGS ()",
		`A001 COPY 1 "Archive"`, "A001 COPY 2:4 INBOX",
		"A001 APPEND INBOX {310}", `A001 APPEND "Sent" (\Seen) {12+}`, `A001 APPEND saved (\Seen) "date" {1}`,
		"A001 SEARCH ALL", "A001 SEARCH UNSEEN", "A001 SEARCH NEW", "A001 SEARCH ALL UNSEEN",
		`A001 SEARCH FROM "alice"`, "A001 SEARCH SUBJECT reset", "A001 SEARCH TEXT password",
		"A001 SEARCH SINCE 1-Feb-2026", "A001 SEARCH CHARSET UTF-8 ALL", "A001 SEARCH NOT SEEN",
		`A001 SEARCH SUBJECT "RESET"`, "A001 SEARCH FROM Alice", "A001 SEARCH LARGER 1000",
		`A001 SEARCH OR FROM "a" TO "b"`, "A001 SEARCH BODY token", "A001 SEARCH HEADER Subject x",
		"A001 UID FETCH 1:* (FLAGS)", "A001 UID STORE 1", "A001 UID COPY 1 INBOX", "A001 UID MOVE 1 INBOX",
		"A001 UID SEARCH ALL", "A001 UID EXPUNGE 1:5",
		`A001 LIST "" "*"`, `A001 LIST "" *`, `A001 LIST "" %`, `A001 LIST "~/Mail/" "%"`, `A001 LIST "" INBOX`,
	)...)
	// STORE with a short tag.
	checkMail(t, true, afterBreak(
		"x1 STORE 1", "V1 STORE 2:3", "1 STORE 1", "ab12cd34 STORE 7", `a STORE 1 +FLAGS (\Deleted)`,
		`tag STORE 1:* -FLAGS (\Seen)`, "A0001 STORE 1", "AB001 STORE 1", "A01 STORE 1  ",
	)...)
}

func TestIMAPCommandsClear(t *testing.T) {
	checkMail(t, false, afterBreak(
		// Flight, aircraft and room codes followed by an ordinary word.
		"A320 LIST", "B737 LIST OF SPARES", `A320 LIST "spares"`, "A320 LIST price and stock",
		"A320 SEARCH", "B737 SEARCH AND RESCUE", "A320 SEARCH RESULTS", "A320 SEARCH FOR CREW",
		"A320 SEARCH ALL AREAS", "A320 SEARCH NEW ROUTES", "A320 SEARCH NOT FOUND", "A320 SEARCH FROM",
		"A320 LOGIN", "A320 LOGIN FAILED", "A320 LOGIN IS NOT WORKING", "A101 LOGIN PAGE ERROR",
		"A320 LOGIN FAILED TODAY",
		"A320 AUTHENTICATE", "A320 AUTHENTICATE your crew badge", "A320 AUTHENTICATE users first",
		"A320 AUTHENTICATE USERS", "A320 AUTHENTICATE PLAINS",
		"A320 SELECT", "A320 SELECT SEATS", "A320 SELECT YOUR SEAT", `A320 SELECT "seat" now`,
		"A320 SELECT INBOXES",
		"A320 FETCH", "A320 FETCH THE LOGS", "A320 FETCH 2 BAGS", "A320 FETCH 2", "A320 FETCH ALL",
		"A320 FETCH 2 FULL CREWS", "A320 FETCH 3 BODY BAGS",
		"B737 SEARCH ON HOLD", "A320 SEARCH TO BE CONTINUED", "A320 SEARCH FROM DUBAI", "A320 SEARCH TEXT BOX",
		"A101 STORE", "A101 STORE HOURS", "A101 STORE 5 BOXES", "A101 STORE 5, aisle 2",
		"A101 STORE 5 FLAGSHIP",
		"A320 COPY", "A320 COPY OF THE MANUAL", "A320 COPY 2 SETS", "A320 COPY 2 INBOX please",
		"A320 APPEND", "A320 APPEND THE REPORT", "A320 APPEND notes {draft}", "A320 APPEND notes {}",
		"A320 UID", "A320 UID MISMATCH", "A320 UID LIST", "A320 UID UID FETCH 1 ALL", "A320 UID EXPUNGE now",
		"A320 LOGOUT", "A320 NOOP", "A320 OK LOGIN completed", "a001 OK SELECT completed",
		"* SEARCH 2 3", "A001 select INBOX", "A001 Select INBOX", "A001 SELECTED INBOX", "A001SELECT INBOX",
		"A01 SELECT INBOX", "A0001 SELECT INBOX", "AB01 SELECT INBOX", "0001 SELECT INBOX",
		// STORE with a short tag: a word before it is a shouted sentence, and a
		// tag of letters only needs the FLAGS item.
		"WE STORE 5", "I STORE 2", "TO STORE 3 BOXES", "a STORE 1", "x1 STORE", "x1 STORE one",
		"x1 STORE 5 BOXES", "abcdefg12 STORE 1", "x-1 STORE 1", "x1 store 1", "R2 STORE 5th floor",
		"WE STORE FLAGS", "WE STORE 5 FLAGSTONES",
	)...)
}

// Ordinary multi-line text that has these words at the start of a line.
func TestMailOrdinaryText(t *testing.T) {
	checkMail(t, false,
		"Agenda:\nTOP 5 priorities\nAUTH rework\nEHLO banner\nHELO check\nRETR timing",
		"TOP SELLERS\nTOP 10 PRODUCTS 2026\nSTORE OPENING HOURS\nCOPY DEADLINE\nSEARCH AND RESCUE",
		"Fleet:\r\nA320 LIST\r\nB737 SEARCH\r\nA330 LOGIN\r\n",
		"name,code,qty\r\nTOP,10,20\r\nRETR,1,2\r\nA320,LIST,3\r\n",
		"2026-02-01 10:00:00 AUTH LOGIN failed\n2026-02-01 10:00:01 MAIL FROM:<a@example.com> accepted",
		"## SMTP\n\n- `EHLO host`\n- `MAIL FROM:<you@example.com>`\n\n**AUTH PLAIN** is off.\n| RETR 1 | get |",
		// Quoted and prefixed transcripts.
		"As requested:\n> EHLO mail.example.com\n> AUTH LOGIN\n> MAIL FROM:<a@example.com>\n"+
			"> RCPT TO:<b@example.com>\n> RETR 1\n> a001 LOGIN alice secret\n> a002 SELECT INBOX",
		"S: 220 mail.example.com ESMTP\nC: EHLO client.example.com\nS: 250 OK\nC: MAIL FROM:<a@example.com>",
		"+OK POP3 ready\n-ERR no such message\n* OK IMAP4rev1\n* 3 EXISTS\na001 OK LOGIN completed",
		// A bounce message that names the commands in its sentences.
		"This is the mail system.\n\n<b@example.com>: host mx.example.com[192.0.2.1] said:\n"+
			"    550 5.1.1 user unknown (in reply to RCPT TO command)\n"+
			"    SMTP error from remote server after RCPT TO:<b@example.com>:\n"+
			"Diagnostic-Code: smtp; 550 5.1.1\nFinal-Recipient: rfc822; b@example.com",
	)
}

// Pasted text that is a command by its shape is flagged: accepted false
// positives, listed in docs/threat-model.md.
func TestMailAcceptedFalsePositives(t *testing.T) {
	checkMail(t, true,
		// Transcripts pasted without a prefix.
		"The log:\n220 mail.example.com ESMTP\nEHLO client.example.com",
		"The log:\n250 OK\nMAIL FROM:<a@example.com>",
		"It failed here:\r\nRCPT TO:<b@example.com>: 550 5.1.1 user unknown",
		"+OK ready\nUSER alice\n+OK\nRETR 1\n-ERR",
		"Server said no:\nAUTH LOGIN\n535 denied",
		"* OK IMAP4rev1\na001 LOGIN alice secret\na001 NO",
		"* 3 EXISTS\na002 SELECT INBOX",
		// Documentation written one command to a line.
		"Send:\n    MAIL FROM:<you@example.com>\n    RCPT TO:you@example.org",
		"```\nEHLO mail.example.com\n```",
		// A line that only happens to have the shape.
		"Charts:\nTOP 10 2026", "Note:\nHELO Mr.Smith", "Ids:\nA101 STORE 5", "Bins:\nR2 STORE 15",
		"Gate:\nB737 SEARCH ALL", "Cabin:\nA320 SEARCH TEXT box", "Form:\nA101 LOGIN page error",
		"SMTP\nAUTH LOGIN\nis disabled", "Status:\nAUTH LOGIN Disabled", "Cols:\n1 STORE 5",
		"Parts:\nA320 FETCH 2 (spare)", "Menu:\nA320 SELECT \"Premium\"",
	)
}

// Command lines the checks do not read: accepted misses, listed in
// docs/threat-model.md. Several are narrowings an attacker can use.
func TestMailAcceptedMisses(t *testing.T) {
	checkMail(t, false, afterBreak(
		// Another case, or a command outside the list.
		"mail from:<a@example.com>", "rcpt to:<b@example.com>", "a001 select inbox",
		"DATA", "VRFY root", "STARTTLS", "AUTH GSSAPI", "USER alice", "DELE 1",
		"a001 EXAMINE INBOX", "a001 CREATE box", `a001 DELETE "box"`, "a001 LOGOUT",
		// More on the line than the command takes.
		"MAIL FROM: a@example.com", "RCPT TO:<>", "PASS secret", "x-1 STORE 1", ". STORE 1",
		"EHLO attacker", "EHLO mail.example.com x", "AUTH PLAIN AGEAYg== x", "AUTH LOGIN;",
		"AUTH LOGIN dXNlcg", "AUTH PLAIN abcdabcd", "AUTH PLAIN ABCDABCD", "A001 AUTHENTICATE PLAIN abcd",
		"RETR 1;", "TOP 1 0 x",
		// IMAP arguments outside the shapes read.
		"A001 SELECT Drafts", "A001 COPY 1 Trash", "A001 FETCH 1 body[]", "A001 LIST INBOX *",
		"A001 SEARCH 1:5", "A001 SEARCH all", "A001 LOGIN alice", "A001 LOGIN alice secret x",
		"A001 SELECT INBOX x", "x1 STORE 1 junk", "a STORE 1", "A001  UID  NOOP",
		// Upper-case words read as a shouted sentence, a mechanism that is not
		// listed, and a FETCH item with text after it.
		"A001 LOGIN ADMIN PASSWORD", "A001 SEARCH SUBJECT PASSWORD", "A001 UID SEARCH FROM ADMIN",
		"A001 AUTHENTICATE X-CUSTOM", "A001 FETCH 1 BODY x", "A001 FETCH 1 ALL x",
	)...)
	// A command with no line break before it.
	checkMail(t, false, "RETR 1", "a001 SELECT INBOX")
}

// The older header check is unchanged.
func TestCRLFHeadersStillFlagged(t *testing.T) {
	checkMail(t, true, "x\r\nSet-Cookie: a=b", "x\n\nLocation: /y")
	checkMail(t, false, "x\r\n Set-Cookie: a=b", "x\nNote: ring bell")
}

// TestMailAndURLChecksLinear runs the mail command check and the URL host
// check on hostile values of up to 1 MiB, the way
// TestInjectionTechniquesLinear does, and then with a hit at the end.
func TestMailAndURLChecksLinear(t *testing.T) {
	blanks := strings.Repeat(" ", 200)
	long := strings.Repeat("a", 200)
	checks := []struct {
		name  string
		match func(string) bool
		tail  string
		units map[string]string
	}{
		{"mail", isCRLF, "RETR 1", map[string]string{
			"breaks":        "\n",
			"blanks":        "\n" + blanks,
			"blank-run":     " ",
			"from":          "\nMAIL FROM:" + blanks,
			"rcpt":          "\nRCPT TO:" + long,
			"rcpt-angle":    "\nRCPT TO:<" + long + " ",
			"greeting":      "\nEHLO " + long,
			"greeting-lit":  "\nHELO [" + long,
			"auth":          "\nAUTH PLAIN " + long + " x",
			"retr":          "\nRETR " + strings.Repeat("1", 200) + "x",
			"top":           "\nTOP 1 1 x",
			"tag":           "\nA001 ",
			"login":         "\nA001 LOGIN \"",
			"login-long":    "\nA001 LOGIN " + long + " " + long + " x",
			"select":        "\nA001 SELECT \"" + long,
			"fetch":         "\nA001 FETCH " + strings.Repeat("1:", 100) + " x",
			"store":         "\nx1 STORE " + strings.Repeat("1,", 100) + " x",
			"append":        "\nA001 APPEND x " + strings.Repeat("{1", 100),
			"append-digits": "\nA001 APPEND x " + strings.Repeat("1", 200) + "}",
			"search":        "\nA001 SEARCH NOT ",
			"list":          "\nA001 LIST \"\" ",
			"uid":           "\nA001 UID UID ",
			// One line, so a check that reads to the end of the line from many
			// places would be quadratic.
			"one-line":      "A001 APPEND x {1} ",
			"one-line-tags": " A001 LOGIN \"",
		}},
		{"url", func(s string) bool { return hostRule(s) != ssrfNone }, " http:localhost", map[string]string{
			"scheme":        "http:",
			"scheme-comma":  ",http:",
			"scheme-slash":  ",http:/",
			"scheme-at":     "=http:@",
			"colons":        ":",
			"excluded":      "xhttp:",
			"long-host":     ",http:" + long,
			"userinfo":      ",http:a@",
			"bracket":       ",http:[",
			"port":          ",http:a:",
			"digits":        ",http:" + strings.Repeat("9", 200),
			"zeros":         ",http:0.",
			"short-numbers": ",http:404 ",
			"dots":          "\u3002",
			"dots-host":     ",http:\u3002",
			"urls-dots":     "http://\uff0e",
			"lead-bytes":    "\u3042",
		}},
	}
	const small, medium, large = 64 << 10, 256 << 10, 1 << 20
	// A quadratic scan of 1 MiB takes tens of seconds.
	lim := wallLimit(250*time.Millisecond, 5*time.Second)
	for _, c := range checks {
		for name, unit := range c.units {
			s := strings.Repeat(unit, small/len(unit))
			m := strings.Repeat(unit, medium/len(unit))
			l := strings.Repeat(unit, large/len(unit))
			// One long authority with no end byte, and one long line.
			for _, v := range []string{s, m, l} {
				if c.match(v) {
					t.Errorf("%s/%s: hit on the hostile value, want none", c.name, name)
				}
			}
			if !c.match(l + "\n" + c.tail) {
				t.Errorf("%s/%s: no hit with %q at the end", c.name, name, c.tail)
			}
			if testing.Short() {
				continue
			}
			run := func(v string) func() { return func() { c.match(v) } }
			superLinear := func() bool {
				ds := bestOf(5, run(s))
				return ds > 200*time.Microsecond && bestOf(5, run(m)) > 8*ds
			}
			if raceSlowdown == 1 && superLinear() && superLinear() && superLinear() {
				t.Errorf("%s/%s: %d bytes took over 8x the time of %d bytes three times: super-linear", c.name, name, len(m), len(s))
			}
			if d := bestOf(3, run(l)); d > lim {
				t.Errorf("%s/%s: %v on %d bytes, want under %v", c.name, name, d, len(l), lim)
			}
		}
	}
	// One authority of 1 MiB, ending in the host that counts.
	one := "http:" + strings.Repeat("a", large) + "@localhost"
	if hostRule(one) != ssrfInternal {
		t.Error("long userinfo: no hit")
	}
	if d := bestOf(3, func() { hostRule(one) }); !testing.Short() && d > lim {
		t.Errorf("long userinfo: %v, want under %v", d, lim)
	}
}
