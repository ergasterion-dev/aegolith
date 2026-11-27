package detect

import (
	"strings"
	"testing"
	"time"
)

// assertSQLTechnique checks the AEG-SQLI-001 technique checks on their own,
// so that a positive libinjection also flags still proves the new check, and
// that a hit reaches SQLi and both ScanText entry points.
func assertSQLTechnique(t *testing.T, want bool, values []string) {
	t.Helper()
	for _, v := range values {
		if got := hasSQLTechnique(v); got != want {
			t.Errorf("hasSQLTechnique(%q) = %v, want %v", v, got, want)
		}
		if !want {
			continue
		}
		if _, ok := SQLi(v); !ok {
			t.Errorf("SQLi(%q) = no hit, want hit", v)
		}
		if !hasRule(ScanText(v), "AEG-SQLI-001") {
			t.Errorf("ScanText(%q) has no AEG-SQLI-001", v)
		}
		if !hasRule(ScanQueryText(v), "AEG-SQLI-001") {
			t.Errorf("ScanQueryText(%q) has no AEG-SQLI-001", v)
		}
	}
}

// assertSQLClean checks that neither SQL rule flags a value at all.
func assertSQLClean(t *testing.T, values []string) {
	t.Helper()
	for _, v := range values {
		for _, hits := range [][]Hit{ScanText(v), ScanQueryText(v)} {
			if hasRule(hits, "AEG-SQLI-001") || hasRule(hits, "AEG-SQLI-002") {
				t.Errorf("ScanText(%q) = %+v, want no SQL hit", v, hits)
			}
		}
	}
}

func TestSQLiPostgresLiteralCast(t *testing.T) {
	assertSQLTechnique(t, true, []string{
		// Every operator after a cast literal.
		`'{"k":1}'::jsonb @> '{"k":1}'`,
		`'{"k":1}'::jsonb <@ '{"k":1,"m":2}'`,
		`'{"k":1}'::jsonb ?| array['k']`,
		`'{"k":1}'::jsonb ?& array['k']`,
		`'{"k":1}'::jsonb #> '{k}'`,
		`'{"k":1}'::jsonb #>> '{k}'`,
		`'{"k":1}'::jsonb -> 'k'`,
		`'{"k":1}'::jsonb ->> 'k'`,
		`'{"k":1}'::jsonb ? 'k'`,
		`'{"k":1}'::jsonb ?"k"`,
		// ::json, no blanks, upper case, a second cast.
		`'{"k":1}'::json->>'k'`,
		`'[7]'::JSON ->> 0`,
		`'{"k":1}'::JsonB@>'{}'`,
		`'7'::json::jsonb`,
		`'7'::json ::json`,
		// Concatenation and element removal.
		`'{}'::jsonb || '{"k":1}'`,
		`'[1]'::json||'2'`,
		`'[4,5]'::jsonb - 1`,
		`'[4,5]'::jsonb -0`,
		// Behind a quote breakout.
		`zz' or '{"k":1}'::jsonb @> '{"k":1}'--`,
		`9 AND '[]'::jsonb <@ '[]'--`,
	})
	assertSQLTechnique(t, false, []string{
		`data->>'name'`,
		`'{}'::jsonb`,
		`'{"k":1}'::json`,
		`SELECT id FROM items WHERE doc @> '{"k":1}'::jsonb`,
		`SELECT id FROM items WHERE doc @> '{"k":1}'::jsonb AND live`,
		`doc->'a'->>'name'`,
		`('{"k":1}'::jsonb)->>'k'`,
		`'{}'::jsonpath @> x`,
		`'{}'::jsonb_ops ->> 'k'`,
		`'{}'::jsonb, then call it`,
		`'{}'::jsonb || other_column`,
		`'{}'::jsonb - other_column`,
		`'{}'::jsonb ? yes`,
		`'{}'::text @> '{}'`,
		`it's a ::json -> thing`,
		`the type is ::jsonb ? 'maybe'`,
	})
}

func TestSQLiPostgresAfterBoolean(t *testing.T) {
	assertSQLTechnique(t, true, []string{
		// After "or" or "and" and a JSON or array literal, each operator
		// prose does not write, before a quote or "array[".
		`or '{"k":1}' @> '{"k":1}'`,
		`and '{"k":1}' <@ '{"k":1,"m":2}'`,
		`OR '{"k":1}' ?| array['k']`,
		`And '{"k":1}' ?& ARRAY['k']`,
		`or '{"k":{"m":1}}' #> '{k}'`,
		`or '{"k":{"m":1}}' #>> '{k,m}'`,
		`and '[1]' <@ array[1,2]`,
		`or '{k}'?|'{k}'`,
		`or '{k}' ?& '{k}'`,
		`and '[1,2]' @> '[1]'`,
		`and ' {1,2}' @> '{1}'`,
		"or\t\n'{}' <@ '{}'",
		`and '{"k":"it''s"}' @> '{}'`,
		// A bare cast after a quote, a digit or ")" before "or"/"and".
		`zz' or '7'::json--`,
		`4 and 'zz'::jsonb`,
		`x) OR '{}'::jsonb#`,
		`a" and '{}'::json`,
	})
	assertSQLTechnique(t, false, []string{
		// Prose that quotes words around "or"/"and" with arrows, questions
		// and handles.
		`Press 'Ctrl' and 'S' -> saves the file`,
		`Choose 'tea' or 'coffee'? 'Either' works`,
		`Ping 'ops' or 'dev' <@U024BE7LH> please`,
		`Mark 'open' and 'done' #> archive`,
		`Pick 'a' or 'b' ->> next page`,
		`Is it 'x' and 'y' @> noon?`,
		// A bare cast after "or"/"and" that follows a word: a code remark.
		`set the default to NULL or '{}'::jsonb`,
		`Use null and '[]'::json as the fallback`,
		`or '{}'::jsonb`,
		// No blank before the literal, other words, no operator.
		`for '{"k":1}' @> x`,
		`color '{"k":1}' @> x`,
		`or'{"k":1}' @> x`,
		`or '{"k":1}' = x`,
		`or '{"k":1}' ? k`,
		`and '{"k":1}', then -> next`,
		`or '{"k":1} @> x`,
	})
}

// sqliBracketProse is developer prose that quotes JSON or bracketed words
// around "or"/"and" next to arrows, questions, table cells, entities and chat
// mentions. Neither SQL rule flags it.
var sqliBracketProse = []string{
	`Should the body be '{}' or '[]'? 'null' fails`,
	`Is the default '[]' or '{}' ? 'x'`,
	`Go to '[Settings]' or '[Account]' -> 'Security'`,
	`Use '{' or '[' -> 'bracket'`,
	`Should we send '{"a":1}' or '{"a":2}'? 'a' is required`,
	`The API returns '{}' or '[]' -> 'empty'`,
	`POST '{"id":1}' and '{"id":2}' ->> 'created'`,
	`Open '[File]' or '[Edit]' ->> "Preferences"`,
	`It accepts '{"ok":true}' and '[]' ? "yes" : "no"`,
	`| Is it '{}' or '[]'?| yes |`,
	`| '[a]' and '[b]'?& more |`,
	`Send '{}' or '[]'?&nbsp;Both work`,
	`Ping '[ops]' or '[dev]' <@U024BE7LH> about it`,
	`Tag '[bug]' or '[task]' <@here>`,
	`Mark '[open]' and '[done]' #> then archive`,
	`Retry '{id}' or '{name}' @> noon`,
	"## Errors\n\n- '{}' or '[]' -> `400`",
}

func TestSQLiPostgresAfterBooleanProse(t *testing.T) {
	assertSQLTechnique(t, false, sqliBracketProse)
	assertSQLClean(t, sqliBracketProse)
}

// TestSQLiPostgresLiteralBound: the literal is read at most 200 bytes.
func TestSQLiPostgresLiteralBound(t *testing.T) {
	lit := func(n int) string { return "'{" + strings.Repeat("a", n-2) + "}'" }
	assertSQLTechnique(t, true, []string{
		lit(200) + "::jsonb @> x",
		"or " + lit(200) + " @> '{}'",
		"1 or " + lit(200) + "::jsonb",
	})
	assertSQLTechnique(t, false, []string{
		lit(201) + "::jsonb @> x",
		"or " + lit(201) + " @> '{}'",
		"1 or " + lit(201) + "::jsonb",
	})
}

func TestSQLiParenCast(t *testing.T) {
	assertSQLTechnique(t, true, []string{
		// A ")" that closes nothing in the value, each cast and each
		// follower.
		`7)::int and 1=1`,
		`7)::integer or true`,
		`z')::bool AND x`,
		`z')::text::int`,
		`7)::int`,
		`7)::INTEGER Or 1`,
		"7)::text  \n",
		// A parenthesised group that holds a select.
		`1 and (select usename from pg_user limit 1)::int`,
		`(SELECT current_user)::text and 1`,
		`(select(chr(65)))::bool or 1`,
		`((select 1))::integer::text`,
	})
	assertSQLTechnique(t, false, []string{
		// Ordinary Postgres expressions: balanced and without a select.
		`(data->>'live')::bool AND removed_at IS NULL`,
		`SELECT count(*)::int`,
		`(total * 100)::integer`,
		`round(avg(score))::int`,
		`it fails on (a)::text or (b)::text`,
		`(a)::int::text`,
		`cast (selected)::int`,
		`a) first b) (x)::int`,
		// A cast or a follower that is not listed.
		`7)::int4`,
		`7)::boolean`,
		`7)::date and 1`,
		`7)::int = 1`,
		`7)::int android`,
		`7)::int, name`,
		`7)::int--`,
		`7) ::int`,
		`7)::int` + strings.Repeat(" ", 130) + "and 1",
	})
}

func TestSQLiGluedKeywordBreakout(t *testing.T) {
	var positives []string
	for _, kw := range []string{"and", "or", "xor", "not", "is", "mod", "glob", "like", "regexp", "rlike", "collate"} {
		positives = append(positives, "zz'"+kw+" flag--", "7'"+strings.ToUpper(kw)+" flag#")
	}
	positives = append(positives,
		"zz'or flag -- -",
		"zz'or flag#  ",
		"zz'or flag --\n",
		"zz'or(flag)#",
		"zz'like%--",
		"zz'or "+strings.Repeat("a", 62)+" --",
	)
	assertSQLTechnique(t, true, positives)
	assertSQLTechnique(t, false, []string{
		"Kids' like it--",
		"I said 'no' or else--",
		// French "d'or" and "l'or".
		"Palme d'or --",
		"La médaille d'or --",
		"Tout ce qui brille n'est pas l'or #",
		"Côte d'Or--",
		// A quoted word closed with no blank after it: an earlier quote.
		"I typed 'yes'and nothing happened --",
		"Try 'Sunset'or the other one #",
		// A longer word, no keyword, a blank, no comment at the end, a quote
		// after the keyword.
		"zz'orange --",
		"zz'ordinary#",
		"zz' or flag--",
		"rock'n'roll --",
		"Pick the kid'or adult size",
		"issue zz'or flag #42",
		"zz'or flag -- thanks",
		`zz'or "flag" --`,
		"zz'or flag' --",
		"zz_'or flag--",
		"'or flag--",
		"zz'or " + strings.Repeat("a", 63) + " --",
		"We can't wait -- see you #",
		"# Release notes\n\nThe users' list isn't sorted. ## Done ##",
	})
}

func TestSQLiSpacedKeywordBreakout(t *testing.T) {
	var positives []string
	for _, kw := range []string{"xor", "mod", "div", "glob", "regexp", "rlike", "similar to", "collate", "sounds like"} {
		positives = append(positives, "zz' "+kw+" flag--", "7' "+strings.ToUpper(kw)+" flag#", "' "+kw+" flag;")
	}
	positives = append(positives,
		"zz'  similar \t to 7 -- -",
		"zz' sounds\nlike 7;  ",
		"admin' mod 1 # ",
		"l'ete' xor 1;",
		"%' mod 1;",
		"-1)' glob x#",
		"zz' mod "+strings.Repeat("a", 62)+" --",
		"zz' mod "+strings.Repeat("a", 63)+";",
	)
	assertSQLTechnique(t, true, positives)
	assertSQLTechnique(t, false, []string{
		// The quote closes a quoted word.
		"I love the 'JEI' mod;",
		"Try the 'Optifine' mod --",
		"add a class to the 'hero' div;",
		"add the 'dist' glob;",
		"I built a 'phone' regexp --",
		"That 'new' sounds like fun --",
		"I want a show like 'Friends' similar to Seinfeld;",
		"WHERE name = 'zz' collate nocase;",
		`$flag = 'a' xor $b;`,
		// A quote written as code opens a string: after a blank or one of
		// ( [ { , = + . : " or a backtick.
		`sql += ' collate nocase';`,
		`console.log(' glob pattern');`,
		`str.replace("' div", "");`,
		"Run it with `' mod 2`;",
		`x[' div '] ;`,
		`{' div ': 1};`,
		`f(a,' xor ');`,
		`s =' div ';`,
		`a+' div ';`,
		`$a.' div ';`,
		`key:' glob ';`,
		// A plural possessive.
		"the kids' sounds like fun --",
		"all the mods' mod list #",
		"the students' collate the pages;",
		// No blank, a longer word, no ending, too far from the ending.
		"zz'xor_flag;",
		"zz' modern art --",
		"zz' division #",
		"zz' similar toys --",
		"zz' sounds likely --",
		"zz' mod flag",
		"zz' mod #42",
		"zz' mod flag; then more",
		"zz' and flag--",
		"zz' mod " + strings.Repeat("a", 63) + " --",
		"zz' mod " + strings.Repeat("a", 64) + ";",
	})
}

func TestSQLiSymbolBreakout(t *testing.T) {
	var positives []string
	for _, op := range []string{"^", "&", "|", "%", "<", ">", "~", "-"} {
		positives = append(positives, "zz' "+op+" flag--", "7' "+op+"  _x9 -- -")
	}
	assertSQLTechnique(t, true, positives)
	assertSQLTechnique(t, false, []string{
		"Menu: 'Mac' & cheese --",
		"'Hamlet' - Shakespeare--",
		"The 'Pro' > Basic --",
		"Kids' - toys--",
		"THE BOSS' - notes --",
		`$sep = ' ^ x--`,
		`printf(' - done --`,
		`title: ' - draft --`,
		"Use the flag ' - verbose --",
		"zz' = flag--",
		"zz' || flag--",
		"zz'^flag--",
		"zz' ^flag--",
		"zz' ^ 7--",
		"zz' ^ two words--",
		"zz' ^ flag#",
		"zz' ^ flag;",
		"zz' ^ flag -- more",
		"zz' ^ flag",
		"I'm here - waiting --",
	})
}

func TestSQLiEscapedQuoteBreakout(t *testing.T) {
	assertSQLTechnique(t, true, []string{
		`\' or version();`,
		`zz\'and sleep(1);`,
		`zz\'  OR  pg_x(1, 'a');`,
		`zz\' or f() ; `,
	})
	assertSQLTechnique(t, false, []string{
		// An earlier quote: the string was opened in the value itself.
		`$q = 'a\' or foo();`,
		`log('Ben\' and jerry(s)');`,
		`' or version();`,
		`zz\' or version()`,
		`zz\' or version(); done`,
		`zz\' or version;`,
		`zz\' or (1);`,
		`zz\' or two words();`,
		`zz\' also version();`,
		`zz\' ordinal();`,
		`it\'s done();`,
	})
}

// sqliTechniqueClean is ordinary text near the new shapes that neither SQL
// rule flags: pass strings, possessives, quoted words, contractions,
// hashtags, issue numbers, Markdown, code in support messages, passwords.
var sqliTechniqueClean = []string{
	"Kids' like it--",
	"I said 'no' or else--",
	`data->>'name'`,
	`'{}'::jsonb`,
	"(total * 100)::integer",
	"the players' boots are in --",
	"We love the 'classic' div; not the new one",
	"Don't forget -- it's today #",
	"#yolo #nofilter #kids'party",
	"Fixed in #42, see the follow-up to #43--",
	"See issue #42 -- the 'mod' key was ignored",
	"## What's new\n\n* the parser's `mod` operator\n* `div` support --",
	"```sql\n-- list the users' rows\n```",
	"My query `doc->>'id'` returns null, why?",
	"console.log('it\\'s done');",
	`$name = 'O\'Brien';`,
	"password: p@ss'W0rd#",
	"Tr0ub4dor&3'--",
	"correct horse' battery#",
	"Palme d'or --",
	"Height 5' 11\" --",
	"set the default to NULL or '{}'::jsonb",
	"Press 'Ctrl' and 'S' -> saves the file",
	`sql += ' collate nocase';`,
	`str.replace("' div", "");`,
	"Use the flag ' - verbose --",
}

func TestSQLiTechniquesOrdinaryText(t *testing.T) {
	assertSQLTechnique(t, false, sqliTechniqueClean)
	var clean []string
	for _, v := range sqliTechniqueClean {
		// libinjection flags these, before this change too.
		switch v {
		case "Tr0ub4dor&3'--", "See issue #42 -- the 'mod' key was ignored", "Height 5' 11\" --":
		default:
			clean = append(clean, v)
		}
	}
	assertSQLClean(t, clean)
}

// sqliTechniqueAcceptedFalsePositives are legitimate texts the new
// AEG-SQLI-001 checks flag (threat model, "SQL techniques added in
// alpha.7"). If one stops matching, update that section.
var sqliTechniqueAcceptedFalsePositives = []string{
	// Postgres JSON expressions on a literal, pasted into a ticket.
	`why does '{"k":1}'::jsonb ? 'k' return true`,
	`merge with '{}'::jsonb || '{"k":1}'::jsonb`,
	`'["a","b"]'::jsonb - 1 drops the second`,
	`cast it: '{}'::json::jsonb`,
	`WHERE id = 1 or '{}'::jsonb`,
	`you can test x and '{a,b}' @> '{a}'`,
	// The same, where a note puts a quote after the operator.
	`type '[a]' or '[b]' #> 'c' at the prompt`,
	`|Is it '[x]' or '[y]'?|'yes'|`,
	// A subquery cast.
	`SELECT (SELECT count(*) FROM items)::int`,
	// A fragment cut after its "(".
	`price)::int`,
	// Typing slips and unmatched apostrophes before a keyword or symbol, in
	// a text that ends like a SQL comment.
	"we can'not do it --",
	"Y'not --",
	"goin' sounds like a plan --",
	"the 5' - approx--",
	// A password of the same shape.
	"Ab9'or#",
	// Code in a text that starts with the quote.
	"' mod 4;",
	`Escape it with \' or retry();`,
}

// sqliTechniqueAcceptedMisses are attack shapes the new AEG-SQLI-001 checks
// do not see (threat model, same section); libinjection may flag some. If one
// starts to hit, update that section.
var sqliTechniqueAcceptedMisses = []string{
	// An uncast literal that is not a JSON object or array.
	`or 'abc' @> 'a'`,
	// After an uncast literal: an arrow, a '?', and an operand that is
	// neither a quote nor "array[".
	`or '{"k":1}' -> 'k'`,
	`or '{"k":1}'->>'k'='1`,
	`or '{"k":1}' ? 'k'`,
	`and '{"k":1}' <@ doc`,
	`or '{a}' @> (select tags)`,
	// A bare cast after a word, or at the start.
	`name or '{}'::jsonb`,
	// A blank before the cast, and an operand before the literal.
	`'{}' ::jsonb @> x`,
	`doc @> '{"k":1}'::jsonb`,
	// A parenthesised cast with balanced parentheses and no select, and a
	// comment after it.
	`1 and (version())::int`,
	`7)::int--`,
	// Breakouts: a second quote first, a plural possessive, no blanks, a
	// number as the operand.
	`'' mod 1--`,
	`users' mod 1--`,
	`users' ^ flag--`,
	`x ' mod 1--`,
	`x ' ^ flag--`,
	`zz'^flag--`,
	`zz' ^ 7--`,
	`d'or 1=1 flag#`,
	`x' and 'a'or flag--`,
	`zz'or 'a'--`,
}

func TestSQLiTechniquesAcceptedFalsePositives(t *testing.T) {
	assertSQLTechnique(t, true, sqliTechniqueAcceptedFalsePositives)
}

func TestSQLiTechniquesAcceptedMisses(t *testing.T) {
	assertSQLTechnique(t, false, sqliTechniqueAcceptedMisses)
}

// The checks see a value after one percent-decoding pass too.
func TestSQLiTechniquesPercentDecoded(t *testing.T) {
	for _, v := range []string{
		`%27%7B%7D%27%3A%3Ajsonb%20%40%3E%20%27%7B%7D%27`,
		`zz%27%20or%20%27%7B%7D%27%20%40%3E%20%27%7B%7D%27`,
		"7%29%3A%3Aint%20and%201",
		"zz%27or%20flag--",
		"zz%27%20mod%20flag%23",
		`zz%5C%27%20or%20f%28%29%3B`,
	} {
		if hasSQLTechnique(v) {
			t.Errorf("hasSQLTechnique(%q) = true, want false before decoding", v)
		}
		if !hasRule(ScanText(v), "AEG-SQLI-001") {
			t.Errorf("ScanText(%q) has no AEG-SQLI-001", v)
		}
	}
}

func TestSQLiTechniquesOnKeys(t *testing.T) {
	for _, k := range []string{"zz' mod flag--", `a)::int or b`, "1,sleep(5)"} {
		if _, ok := KeySQLi(k); !ok {
			t.Errorf("KeySQLi(%q) = no hit, want hit", k)
		}
	}
}

func TestSQLiNestedDelay(t *testing.T) {
	var positives []string
	// Every context, for both functions and every argument start.
	for _, before := range []string{
		"f(1),", "9,", "(select(", "(SELECT(", "(select ", "select ", "SELECT\t", "x and ", "x AND\n ", "x or ", "order by ", "if(", "IF(",
	} {
		positives = append(positives, before+"sleep(5)", before+"BENCHMARK(2000000,md5(1))")
	}
	for _, arg := range []string{
		"5)", " 5 )", "5.5)", "0x5)", "0b101)", "1e1)", "2e+0)", "5*1)", "9-4)", "5+0)", "10/2)", "7%4)", "5|0)", "5&7)", "5^0)",
		"1<<2)", "5>0)", "5=5)", "5!=0)", "(5))", "mod(9,4))", "MOD(9,4))", "select 5))", "SeLeCt(5)))",
	} {
		positives = append(positives, "x or sleep("+arg, "x or benchmark("+arg)
	}
	positives = append(positives,
		"x or"+strings.Repeat(" ", 128)+"sleep(5)",
		"x or sleep("+strings.Repeat(" ", 127)+"5)",
		"x%20or%20sleep%285%29",
	)
	for _, v := range positives {
		if !hasRule(ScanText(v), "AEG-SQLI-002") {
			t.Errorf("ScanText(%q) has no AEG-SQLI-002", v)
		}
		if !hasRule(ScanQueryText(v), "AEG-SQLI-002") {
			t.Errorf("ScanQueryText(%q) has no AEG-SQLI-002", v)
		}
	}
	negatives := []string{
		"(sleep (2))",
		"warmup, (sleep (2)), cooldown",
		"(sleep(2))",
		"sleep(5)",
		"call sleep(5) twice",
		// The list of contexts is exact: blanks after a comma, other words
		// and glued words.
		"9, sleep(5)",
		"f(1), sleep(5)",
		"x,sleep(5)",
		"for sleep(5)",
		"command sleep(5)",
		"nearby sleep(5)",
		"preselect sleep(5)",
		"elsif(sleep(5)",
		"(selectsleep(5)",
		"select(sleep(5)",
		"x andsleep(5)",
		"x or_ sleep(5)",
		"x or" + strings.Repeat(" ", 129) + "sleep(5)",
		// Other names, a blank before "(", no "(".
		"x or sleeps(5)",
		"x or usleep(5)",
		"x or my_sleep(5)",
		"x or sleep (5)",
		"x or sleep 5",
		"x or benchmarks(5)",
		// Arguments that are prose, a name or empty.
		"eat and sleep(8 hours)",
		"eat and sleep(8h)",
		"eat and sleep(8hrs)",
		"rest or sleep(2 x 4)",
		"x or sleep(n)",
		"x or sleep()",
		"x or sleep(modern)",
		"x or sleep(mod)",
		"x or sleep(selected)",
		"x or sleep(5",
		"x or sleep(0x)",
		"x or sleep(5 div 1)",
		"x or sleep(" + strings.Repeat(" ", 129) + "5)",
		"eat, sleep(8), repeat",
	}
	for _, v := range negatives {
		if hasRule(ScanText(v), "AEG-SQLI-002") {
			t.Errorf("ScanText(%q) has AEG-SQLI-002, want none", v)
		}
	}
	assertSQLClean(t, []string{
		"warmup 5,sleep (8), cooldown",
		"I run, eat and sleep (8 hours) daily",
	})
}

// sqlDelayAcceptedFalsePositives are legitimate texts the nested delay check
// flags: the same family as "eat, sleep(8), repeat", which libinjection
// flags (threat model, "SQL techniques added in alpha.7").
var sqlDelayAcceptedFalsePositives = []string{
	"eat and sleep(8)",
	"nap or sleep(8), your call",
	"recover by sleep(8)",
	"Day 1,sleep(8)",
	"(rest),sleep(8)",
	"work and sleep(7-9)",
}

var sqlDelayAcceptedMisses = []string{
	// A blank after the comma, or between the name and "(".
	"9, sleep(5)",
	"x or sleep (5)",
	// A comment as the blank, an operator context, a first argument that is a
	// name or another function.
	"x or/**/sleep(5)",
	"x||sleep(5)",
	"x or sleep(@d)",
	"x or sleep(floor(5))",
	"x or sleep(5 div 1)",
}

func TestSQLiNestedDelayAccepted(t *testing.T) {
	for _, v := range sqlDelayAcceptedFalsePositives {
		if !hasRule(ScanText(v), "AEG-SQLI-002") {
			t.Errorf("ScanText(%q) has no AEG-SQLI-002: update the threat model", v)
		}
	}
	// The older false positive of the same family is libinjection's alone.
	if hits := ScanText("eat, sleep(8), repeat"); !hasRule(hits, "AEG-SQLI-001") || hasRule(hits, "AEG-SQLI-002") {
		t.Errorf("ScanText(eat, sleep(8), repeat) = %+v, want AEG-SQLI-001 only", hits)
	}
	for _, v := range sqlDelayAcceptedMisses {
		if hasRule(ScanText(v), "AEG-SQLI-002") {
			t.Errorf("ScanText(%q) has AEG-SQLI-002: an accepted miss now hits; update the threat model", v)
		}
	}
}

// TestNewSQLiChecksLinear: the Postgres, breakout and delay checks stay
// linear on 1 MiB hostile values, and still find an attack at the end of one.
func TestNewSQLiChecksLinear(t *testing.T) {
	check := func(s string) bool { return hasSQLTechnique(s) || hasSQLToken(s) }
	units := map[string]string{
		"quotes":          "'",
		"or-quote":        "or '",
		"or-open-literal": "or '" + strings.Repeat("a", 199),
		"or-pairs":        "or '' ",
		"or-literal":      "or '{}' x ",
		"or-operator":     "or '{}' @> x ",
		"or-array":        "or '{}' ?| array ",
		"or-operand-gap":  "or '{}' <@" + strings.Repeat(" ", 200),
		"or-blanks":       "or" + strings.Repeat(" ", 200) + "'",
		"blanks-quote":    strings.Repeat(" ", 127) + "'{}'",
		"cast":            "::json",
		"cast-quote":      "'::json",
		"cast-op":         "'{}'::jsonb x ",
		"cast-blanks":     "'{}'::jsonb" + strings.Repeat(" ", 200),
		"cast-chain":      "'::json x::jsonb ",
		"paren-cast":      "()::int x ",
		"paren-open":      "(",
		"paren-close":     ")",
		"paren-select":    "(select ",
		"paren-cast-gap":  "()::int" + strings.Repeat(" ", 200),
		"dashes":          "-",
		"dash-blank":      "- ",
		"hashes":          "# ",
		"semicolons":      "; ",
		"glued":           "1'or ",
		"apostrophes":     "a'a",
		"escaped":         `\' or a ( `,
		"delay-context":   "and sleep(",
		"delay-digits":    "1,sleep(1x ",
		"delay-blanks":    "or" + strings.Repeat(" ", 127) + "sleep(" + strings.Repeat(" ", 127),
		"delay-comma":     "),benchmark(9 x ",
		"delay-names":     "sleep(",
	}
	tails := []string{
		` zz or '{}' @> '{}'`, ` '{}'::jsonb -> 'k'`, ` (select 1)::int`, ` x or sleep(5)`,
	}
	const small, medium, large = 64 << 10, 256 << 10, 1 << 20
	// A quadratic scan of 1 MiB takes tens of seconds.
	lim := wallLimit(250*time.Millisecond, 5*time.Second)
	for name, unit := range units {
		s := strings.Repeat(unit, small/len(unit))
		m := strings.Repeat(unit, medium/len(unit))
		l := strings.Repeat(unit, large/len(unit))
		for _, end := range []string{"", " --", " #", " ;", " );"} {
			if check(l + " ." + end) {
				t.Errorf("%s: hit on the hostile value ending %q, want none", name, end)
			}
		}
		for _, end := range tails {
			if !check(l + " ." + end) {
				t.Errorf("%s: no hit with %q at the end", name, end)
			}
		}
		if testing.Short() {
			continue
		}
		// The growth ratio is measured on the smaller sizes: their runs
		// are short enough to finish undisturbed on a loaded machine.
		for _, end := range []string{" .", " . --", " . );"} {
			sv, mv, lv := s+end, m+end, l+end
			f := func(v string) func() { return func() { check(v) } }
			slow := func() bool {
				ds, dm := bestOf(5, f(sv)), bestOf(5, f(mv))
				return ds > 200*time.Microsecond && dm > 8*ds
			}
			if raceSlowdown == 1 && slow() && slow() && slow() {
				t.Errorf("%s: %d bytes took over 8x the time of %d bytes three times: super-linear", name, len(mv), len(sv))
			}
			if d := bestOf(3, f(lv)); d > lim {
				t.Errorf("%s: %v on %d bytes, want under %v", name, d, len(lv), lim)
			}
		}
	}
	// One long run of each kind after a first quote: no unit repeats.
	for name, l := range map[string]string{
		"one-glued":        "zz'or" + strings.Repeat(" ", large) + "--",
		"one-spaced":       "zz' mod" + strings.Repeat(" ", large) + "x;",
		"one-two-words":    "zz' similar" + strings.Repeat(" ", large) + "x --",
		"one-symbol":       "zz' ^ " + strings.Repeat("a", large) + " .--",
		"one-escaped":      `zz\' or ` + strings.Repeat("a", large) + ";",
		"one-trailing":     "zz' mod x" + strings.Repeat("- ", large/2) + ".",
		"one-delay-digits": "x or sleep(" + strings.Repeat("1", large),
	} {
		if d := bestOf(3, func() { check(l) }); !testing.Short() && d > lim {
			t.Errorf("%s: %v on %d bytes, want under %v", name, d, len(l), lim)
		}
	}
}

// sqliTechniqueWorst are 8 KiB inputs that make the new checks do the most
// work without matching.
var sqliTechniqueWorst = []struct{ name, v string }{
	{"or-open-literal", strings.Repeat("or '"+strings.Repeat("a", 199), 8<<10/203)},
	{"or-quote", strings.Repeat("or '' ", 8<<10/6)},
	{"cast", strings.Repeat("'{}'::jsonb x ", 8<<10/14)},
	{"cast-no-quote", strings.Repeat("'::json", 8<<10/7)},
	{"paren-cast", strings.Repeat("()::int x ", 8<<10/10)},
	{"apostrophes", strings.Repeat("a'a", 8<<10/3) + " --"},
}

func BenchmarkSQLTechnique(b *testing.B) {
	for _, in := range sqliTechniqueWorst {
		b.Run(in.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(in.v)))
			if hasSQLTechnique(in.v) {
				b.Fatal("the input matches, want a worst case without a match")
			}
			for b.Loop() {
				hasSQLTechnique(in.v)
			}
		})
	}
}
