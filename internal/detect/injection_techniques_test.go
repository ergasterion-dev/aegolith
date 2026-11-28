package detect

import (
	"strings"
	"testing"
	"time"
)

// checkTechnique asserts that the technique check match, the rule's
// detector and ScanText agree on v: flagged by all three, or by none.
func checkTechnique(t *testing.T, rule string, match func(string) bool, detect func(string) (Hit, bool), want bool, values []string) {
	t.Helper()
	for _, v := range values {
		if got := match(v); got != want {
			t.Errorf("technique check(%q) = %v, want %v", v, got, want)
		}
		h, ok := detect(v)
		if ok != want || ok && h.RuleID != rule {
			t.Errorf("detector(%q) = %+v %v, want %s %v", v, h, ok, rule, want)
		}
		if got := containsRule(ScanText(v), rule); got != want {
			t.Errorf("ScanText(%q) has %s = %v, want %v", v, rule, got, want)
		}
	}
}

func checkPerl(t *testing.T, want bool, values ...string) {
	t.Helper()
	checkTechnique(t, "AEG-SSTI-001", hasPerlInterpolation, SSTI, want, values)
}

func checkPHPCall(t *testing.T, want bool, values ...string) {
	t.Helper()
	checkTechnique(t, "AEG-CODEI-001", hasPHPDynamicCall, CodeI, want, values)
}

func checkLDAPTechnique(t *testing.T, want bool, values ...string) {
	t.Helper()
	checkTechnique(t, "AEG-LDAP-001", hasLDAPTechnique, LDAP, want, values)
}

// --- Perl interpolation ---

func TestPerlInterpolation(t *testing.T) {
	checkPerl(t, true,
		"@{[x]}",
		"@{[ 7*7 ]}",
		"@{[ scalar localtime ]}",
		"@{ [ reverse 'abc' ] }",
		"@{\t \t[`hostname`]}",
		"name=@{[ getppid ]}&x=1",
		"say \"@{[ lc 'ABC' ]}\"",
		// No closing "}" is needed, and a subscript may follow the "]".
		"@{[ getppid ]",
		"@{[list][0]}",
		"@{[ $values[0] ]}",
		// A type-like word with nothing a PowerShell key would put after it.
		"@{[time]}",
		"@{[time] }",
		"@{[time]->[0]}",
		// A "}" later in the content is Perl; only a leading one is LaTeX.
		"@{[ sort { $a <=> $b } @list ]}",
		// Content of 1 to 128 bytes.
		"@{["+strings.Repeat("a", 128)+"]}",
		"@{[ "+strings.Repeat("a", 126)+" ]}",
		// A later "@{[" is read after one that does not match.
		"@{[]} @{[ time ]}",
	)
}

func TestPerlInterpolationClear(t *testing.T) {
	checkPerl(t, false,
		"@{}",
		"@{[]}",
		"@{["+strings.Repeat("a", 129)+"]}",
		"@{[ "+strings.Repeat("a", 127)+" ]}",
		"@{[a\nb]}",
		"@{[a\rb]}",
		"@{[ unterminated",
		"@ {[x]}",
		"@(1,2)[0]",
		"@{x[0]}",
		"git show HEAD@{1}",
		"print \"@{$ref}\"",
		// PowerShell hashtables, plain and with a typed key.
		"@{ Name = 'web'; Ports = @(80, 443) }",
		"$h = @{n='Size';e={$_.Length}}",
		"@{[string]'a' = 1}",
		`@{ [string]"a" = 1 }`,
		"@{ [int]$id = 'x' }",
		"@{[char]65 = 'A'}",
		"@{[System.Int32] 1 = 'one'}",
		"@{[string]::Empty = 'none'}",
		"@{ [guid](New-Guid) = 1 }",
		"@{[my_type]x = 1}",
		// A LaTeX column specification with a bracket.
		`\begin{tabular}{@{[}c@{]}}`,
	)
}

// --- PHP dynamic calls ---

// phpListed are the function names the quoted and unquoted call forms read.
var phpListed = []string{
	"system", "exec", "shell_exec", "passthru", "popen", "proc_open", "assert", "eval", "phpinfo",
	"create_function", "call_user_func",
}

func TestPHPListedNameCalls(t *testing.T) {
	if len(phpListed) != len(phpFuncNames) {
		t.Fatalf("phpFuncNames has %d names, the test lists %d", len(phpFuncNames), len(phpListed))
	}
	for _, n := range phpListed {
		upper := strings.ToUpper(n)
		checkPHPCall(t, true,
			// A quoted name in parentheses, called.
			"('"+n+"')(1)",
			`("`+upper+`")($v)`,
			";('"+n+"')('x')",
			// A quoted name directly called.
			"'"+n+"'(1)",
			`x="`+upper+`"($v)`,
			// An unquoted name in parentheses, called with a string, a
			// variable or as a whole statement.
			"("+n+")('x')",
			"("+upper+")( \"x\")",
			"("+n+")(\n$v)",
			"("+n+")($$v)",
			"("+n+")(${v})",
			"("+n+")(x);",
			"("+n+")();",
		)
		checkPHPCall(t, false,
			"("+n+")(x)",
			"("+n+")($5)",
			"('"+n+"') (1)",
			"('"+n+"s')(1)",
			"('x"+n+"')(1)",
			"(x"+n+")('a')",
			"('"+n+`")(1)`,
			"the "+n+"(x) call",
		)
	}
}

// TestPHPNamedCallAfterWord: when the first "(" follows a word, it opens an
// argument list, as in JavaScript.
func TestPHPNamedCallAfterWord(t *testing.T) {
	checkPHPCall(t, false,
		"require('assert')(value);",
		"require('assert')(value, 'value is required');",
		"export default connect('system')(Settings);",
		"const run = util.promisify(exec)('npm ci');",
		"wrap(system)(options);",
		// Only the words themselves keep the unquoted form read.
		"xecho(system)('x')",
		"preturn(system)('x')",
	)
	checkPHPCall(t, true,
		// A string or variable argument of the second call.
		"require('assert')($x)",
		"echo('system')('x')",
		"return('exec')($c)",
		// echo, print and return, after which PHP starts an expression.
		"echo(system)('x')",
		"PRINT(exec)($c)",
		"return(system)(x);",
		// A ")" or "]" before the "(" is no word.
		"x)(system)('a')",
		"a[0](system)('a')",
	)
}

func TestPHPCallStatementEnd(t *testing.T) {
	checkPHPCall(t, true,
		// The call's own ")" is the one followed by ";".
		"(system)(base64_decode(x));",
		"(system)(a(b(c))); more",
		"(system)(x) ; (system)(y);",
		// An inner call that ends a statement does not hide an outer one.
		"(system)((eval)(x));",
		strings.Repeat("(", 5)+"(system)(x);"+strings.Repeat(")", 9),
		// The call may be long.
		"(system)(f("+strings.Repeat("a", 5000)+"));",
	)
	checkPHPCall(t, false,
		"(system)(x) ;",
		"(system)(x)); more",
		"(system)(f(x); y",
		"(system)(f(x));"[:14],
		"((system)(x));",
		"(system)(x), b();",
	)
}

func TestPHPFixedShapes(t *testing.T) {
	checkPHPCall(t, true,
		"[system][0](x)",
		"a=[SYSTEM][0]('x')",
		"<? php run();",
		"<?\necho 1;",
		"<?\r\n\tprint 1;",
		"<? ECHO $x ?>",
		"<?  system ('x');",
		"<?\vexec('x');",
		"<?\fphpinfo();",
		"<? $x = 1;",
		"<? $_GET;",
		"<? ${'x'} = 1;",
		"<? $$x = 1;",
		"<? xml ?> <? echo 1;",
	)
	checkPHPCall(t, false,
		"[systemd][0](x)",
		"[system][1](x)",
		"[system][0] (x)",
		"[exec][0](x)",
		"<?xml version=\"1.0\"?>",
		"<?xml-stylesheet href=\"a.xsl\"?>",
		"<? xml ?>",
		"<?$x",
		"<?echo 1",
		"<? ",
		"<? $5",
		"<? $ 5",
		"<? $$",
		"List<? extends Number>",
		"Map<?, ?> m",
		"is x <? y",
	)
}

func TestPHPVariableCalls(t *testing.T) {
	checkPHPCall(t, true,
		// "${...}" with a string or variable argument, or ending a statement.
		"${'sys'.'tem'}('x')",
		`${x}("a")`,
		"${x}($a)",
		"${x}( $a )",
		"${x}(a);",
		"${x}(f(a));",
		"${x}();",
		"${_GET['f']}($_GET['a'])",
		"${${y}}('x')",
		"${ x[0] }('a')",
		"${a.b}('x')",
		"${a b}(${c})",
		"${x}/*c*/('a')",
		"${x}/**//* d */($a)",
		// "$$name" the same way.
		"$$f('x')",
		"$$f($a)",
		"$$f(base64_decode($a));",
		"$$$f($a)",
		";$$f/* c */('x')",
		"$$f ; $$g($a)",
		"x .$$f('a')",
		"'.$$f($a).'",
		"echo $$eval_it('x')",
		// "$name" with indexes: any argument.
		"$a[0](1)",
		"$a{1}(x)",
		"$a[1][2](x)",
		"$a['k']{0}(x)",
		"$a[$b[0]](x)",
		"$a[b{c}](x)",
		"$_GET[a](x)",
		"$GLOBALS['x'](1)",
		"$__[_](1)",
		"$_[1]{2}[3](x)",
		"$$a[0](x)",
		"$a[0]/* c */(x)",
		"$a["+strings.Repeat("1", 5000)+"](x)",
		"'.$_GET[a]($_GET[b]).'",
		"x.$_POST['a'](1)",
		"x.$GLOBALS['a'](1)",
		// LaTeX-like "{" subscripts with a PHP argument.
		"$x_{0}('a')",
		"$x_{0}($a)",
		// Names that only look like a subscript.
		"$_{0}(x)",
		"$__{0}(x)",
		"$x_[0](x)",
		"$x_1{0}(x)",
		"$x_[0]{1}(x)",
		// "@$name": any argument.
		"@$f(x)",
		"=@$f_2/*x*/(1)",
		"@$f()",
		// "@$name" after a word, with a string or variable argument.
		"echo@$f($a)",
		"x@$f('a')",
		// "$_name" with a string or variable argument, or ending a statement.
		"$_f('x')",
		"$_f($a)",
		"$_f(x);",
		"=$_a1/**/('x')",
		"'.$_f($a)",
		// One capital letter and "[" with a PHP argument.
		"$E['x']('a')",
		"$A[0]($b)",
		// Not a single capital letter before "[".
		"$e[0](1)",
		"$AB[0](1)",
		"$A{0}(1)",
		// A second form after one that does not match.
		"$t('x') $a[0](1)",
		"${a}(b) ${c}('d')",
		// A stray bracket elsewhere does not move the pairs.
		"}] $a[0](1)",
		"[{ $a[0](1)",
		"{ ${x}('a')",
		"$a[}](1)",
	)
}

func TestPHPVariableCallsClear(t *testing.T) {
	checkPHPCall(t, false,
		// The pass strings of the shape.
		"$t('x')",
		"$emit('y')",
		"$('div')",
		"$$('div')",
		"$_('id')",
		"Operating (system)(Linux)",
		"Total ${amount}(incl. tax)",
		// A bare "$name(" call is not a dynamic call.
		"$f($a);",
		"this.$emit('change', $event);",
		// "${...}" with other arguments, or not directly called.
		"${a}(b)",
		"${a}()",
		"${a}(1)",
		"${a}($5 off)",
		"${a}($$)",
		"${SCRIPT}($$): started",
		"${a} ('x')",
		"${a}/*c*/ ('x')",
		"${a}/*('x')",
		"${a}.b('x')",
		"${a('x')",
		"$a}('x')",
		"{a}('x')",
		"${}()",
		"`${count} item(s)`",
		// Template interpolation: a plain path, then "${".
		"${name}(${id})",
		"label = `${user.name}(${user.id})`;",
		"return `${fn_1}(${args});`",
		`echo "${NAME}(${PID}) started"`,
		"`${name}($${price})`",
		"`${user?.name}(${user?.id});`",
		// "$$name": LaTeX display math and jQuery-style names.
		"$$f(x) = x^2$$",
		"$$P(A|B) = \\frac{P(B|A)P(A)}{P(B)}$$",
		"$$E(X)$$",
		"$$f(0) = 1$$",
		"$$f ('x')",
		// Browser automation and member access.
		"await page.$$eval('a', els => els.length);",
		"const n = await page\n  .$$eval('li', f);",
		"$$eval('a', f)",
		"page?.$$eval(sel, f);",
		"$scope.$$postDigest(function () { done(); });",
		"a.b().$$watch('x')",
		"list[0].$$init($el);",
		"await page.$eval('#id', el => el.value);",
		// "$name" with indexes: not called, called through a member, empty
		// index, or no name.
		"$el[0].focus();",
		"$a[0]",
		"$a[0] (x)",
		"$a[0]; f(x)",
		"$a[0].f('x')",
		"$a[](x)",
		"$a{}(x)",
		"$a[0][](x)",
		"$a[0(x)",
		"$a0](x)",
		"$[0](x)",
		"$5[0](x)",
		"$(this)[0](x)",
		"$a .[0](x)",
		"this.$refs['form'](x);",
		"return this.$scopedSlots['item'](props);",
		"this.$slots[name]()",
		"vm?.$listeners['click']('a')",
		// LaTeX subscripts.
		"$a_{n}(x)$",
		`$f_{\theta}(x)$`,
		"$x_{i}(t) + y_{i}(t)$",
		"$T_{n}(1) = 0$",
		// A LaTeX symbol applied to a bracket and a factor.
		"$E[X](1 - E[X])$",
		"$P[A](1-P[A])$",
		"$H[f](x)[0](y)$",
		// "@" forms that are not calls, and passwords.
		"@$f",
		"@$(date)",
		"@$$f(x)",
		"my @$list;",
		"P@$word(2024)",
		"ssh admin@$host(primary)",
		"Qa@$z(x);",
		// "$_name": definitions, member calls and other arguments.
		"$_update(value) { this.v = value; }",
		"this.$_mixin_load('users');",
		"vm?.$_f($a)",
		"$_f(x)",
		"$_ (x);",
		"$_(x);",
		// Shell, Makefile and PowerShell text.
		"echo $(date) ${HOME}/bin",
		"$$(echo x)",
		"\t@echo $$HOME ($(USER))",
		"$($obj.Name) ('x')",
		"cost: $100(approx) or US$(5)",
		// A bracket at the start of the value follows no "$".
		"[docs](https://example.com) cost $5",
		"{a}('x') and $y",
		"[0](x) $y",
	)
}

// TestPHPSuppressedCall: "@$name(" takes any argument only where PHP's error
// suppression operator stands, at the start of the value or after white space
// or one of ";({,=.". After any other byte, as in a password, the argument
// must start with a quote or a variable.
func TestPHPSuppressedCall(t *testing.T) {
	for _, lead := range []string{"", " ", "\t", "\n", "\r", "\v", "\f", ";", "(", "{", ",", "=", "."} {
		v := "k" + lead + "@$f(1)"
		if lead == "" {
			v = "@$f(1)"
		}
		checkPHPCall(t, true, v)
	}
	for _, lead := range []string{
		"a", "Z", "7", "_", "!", "#", "$", "%", "^", "&", "*", ")", "}", "[", "]", "-", "+", "~", "`",
		"'", `"`, "\\", "|", ":", "?", "/", "<", ">", "@", "é",
	} {
		checkPHPCall(t, false,
			"k"+lead+"@$f(1)",
			"k"+lead+"@$f(x)",
			"k"+lead+"@$f()",
			"k"+lead+"@$f(x);",
		)
		checkPHPCall(t, true,
			"k"+lead+"@$f('x')",
			"k"+lead+`@$f("x")`,
			"k"+lead+"@$f($x)",
		)
	}
	checkPHPCall(t, false,
		// Passwords.
		"!@$%^&*()",
		"!@$Secret(2024)",
		"my pass !@$Secret(2024)",
		"#@$Ab(",
		"#@$Ab(1)",
		"Zq!@$w(rd)9",
		"1!2@$Qwer(ty)",
		"~!@$Pass(word)!",
		"%40$%40 !@$_Under(9)",
		"pw: !@$Aa(x); next",
		// Prose with no call.
		"cc (@$lead) please",
		"ping @$lead (team lead) today",
		"the @$-sign (at-dollar) key",
		"offer: @$5(each) or @$ 7 (two)",
		"buy 3 @$(price) each",
	)
}

// --- LDAP ---

// ldapShapes build one value of each attribute shape around attr.
var ldapShapes = map[string]func(attr string) string{
	"close-approx":   func(a string) string { return "x)(" + a + "~=y" },
	"close-presence": func(a string) string { return "x)(" + a + "=*" },
	"close-not":      func(a string) string { return "x)!(" + a + "=y" },
	"close-and":      func(a string) string { return "x)&(" + a + "~=y" },
	"close-or-ge":    func(a string) string { return "x)|(" + a + ">=1" },
	"close-and-le":   func(a string) string { return "x)&(" + a + "<=1" },
	"open-or":        func(a string) string { return "(|(" + a + "=y" },
	"open-and":       func(a string) string { return "(&(" + a + "=y" },
	"open-not":       func(a string) string { return "(!(" + a + "=y" },
	"extensible":     func(a string) string { return a + ":1.2.3:=y" },
}

func TestLDAPAttributeBounds(t *testing.T) {
	for name, shape := range ldapShapes {
		t.Run(name, func(t *testing.T) {
			checkLDAPTechnique(t, true,
				shape("u"),
				shape("objectClass"),
				shape("a1-b2"),
				shape("a"+strings.Repeat("1", 40)),
			)
			checkLDAPTechnique(t, false,
				shape("a"+strings.Repeat("1", 41)),
				shape(strings.Repeat("a", 200)),
				shape(""),
				shape("1uid"),
				shape("-uid"),
				shape("_uid"),
				shape(".uid"),
			)
		})
	}
	// "." and "_" are attribute bytes, but a dotted name before an ordering
	// operator is read as code.
	checkLDAPTechnique(t, true,
		"x)(a.b_c=*",
		"x)!(a.b_c=y",
		"(|(a.b_c=y",
		"x)&(a.b_c~=y",
		"x)|(a_c>=1",
		"a.b_c:1.2.3:=y",
	)
	checkLDAPTechnique(t, false,
		"x)|(a.b>=1",
		"x)&(a.b<=1",
	)
}

func TestLDAPTechniques(t *testing.T) {
	checkLDAPTechnique(t, true,
		"x)(&)",
		"x)(|)",
		")(&)(uid=1",
		"memberOf:1.2.840.113556.1.4.1941:=cn=g",
		"x:2.5.13.5:=y",
		"(groupType:1.2.840.113556.1.4.804:=4)",
		"=cn:10.20.30.40:=y",
		// An unterminated filter, and an empty value.
		"(|(uid=",
		"x)!(cn=",
		"x)(cn=*)(sn=1",
		// The ":dn:" form, whose last name before the OID is "dn".
		"o:dn:2.5.13.5:=y",
		// A value with blanks and punctuation.
		"(|(cn=Ann Lee, sales)",
		// A later match is read after one that does not.
		"if(!(n=read())) (|(uid=1",
		"a==b)|(c=1) x)|(d=2",
	)
}

func TestLDAPTechniquesClear(t *testing.T) {
	checkLDAPTechnique(t, false,
		// The pass strings of the shape.
		"f(x)(y=2)",
		"Pages (intro)(page=4)",
		// Plain filters and nested prose.
		"(uid=jdoe)",
		"(see (a) (b=1))",
		"((cn=a))",
		"(a)(b)",
		"x)(y~ =1",
		"x)(y = *",
		"x)(y>=2",
		"x)(y<=2",
		"x) |(y=1",
		"x)| (y=1",
		"x)&&(y=1",
		"x)||(y>=1",
		"x)+(y=1",
		"( |(y=1",
		"(~(y=1",
		"(!!(y=1",
		"(|(y>=1",
		"(&(y~=1",
		"(!(y<=1",
		"(|(y)=1",
		"x)(&&)",
		"x)(& )",
		"x)(!)",
		"(a)(|b)",
		"fn(&)",
		// Comparisons in C, Go, Java, JavaScript and R.
		"if(!(x==1)) return;",
		"if(!(n==null||n==0))",
		"(x==1)|(y==2)",
		"ok=(a)&&(b==1)",
		"if (a&&(b=next())) {}",
		// An assignment of a call or a group is code.
		"if(!(n=read()))",
		"while(!(line=in.readLine()))",
		`if(!(fp=fopen(p,"r")))`,
		"if(!(p=obj->get()))",
		"if(!(s=std::move(t)))",
		"if(!(ok=check (x)))",
		"if(!(n=(a+b)))",
		"x)|(total=sum(y))",
		"x)(y~=f(z))",
		"x)(y=**(z))",
		"if (!(n = read()))",
		"while((c=getchar())!=EOF)",
		// Attribute access in data-frame code.
		"df[(df.age>=18)&(df.score<=50)]",
		"df[(df.a>0)&(df.b>=2)]",
		// OID forms that are not extensible matches.
		"x := 1",
		"a:=b",
		"a:1:=b",
		"a:1.2:=b",
		"a:1..2.3:=b",
		"a:.1.2.3:=b",
		"a:1.2.3.:=b",
		"a:1.2.3=b",
		"a:1.2.3 :=b",
		"a :1.2.3:=b",
		":1.2.3:=b",
		"std::=1.2.3",
		"v1.2.3:=b",
	)
}

// --- accepted false positives and misses ---

// TestInjectionTechniqueAcceptedFalsePositives pins the ordinary text the
// three checks still flag; docs/threat-model.md lists it.
func TestInjectionTechniqueAcceptedFalsePositives(t *testing.T) {
	checkPerl(t, true,
		// Perl and LaTeX text.
		`print "Now: @{[ scalar localtime ]}\n";`,
		`\begin{tabular}{l@{[mm]}r}`,
	)
	checkPHPCall(t, true,
		// JavaScript template text whose first part is not a plain path.
		"`${row[0]}(${row[1]})`",
		"const label = `${user.name}('${user.role}')`;",
	)
	checkLDAPTechnique(t, true,
		// C and Objective-C assignments without blanks.
		"while(!(c=*p)) next();",
		"if(!(self=[super init]))return nil;",
	)
	checkPHPCall(t, true,
		// PHP in a support message.
		"$callbacks[$event]($payload);",
		"$handlers['save']($request)",
		"call_user_func is not needed: $$method('x')",
		"<? echo $title ?>",
		// Perl.
		"$dispatch{$cmd}($arg)",
		// JavaScript and jQuery.
		"$scope[fnName](data);",
		"$this[method]($el);",
		"const q = `${table}(\"id\", \"name\")`;",
		"code += `${fnName}();`",
		"$_reset();",
		// A price template.
		"${amount}($currency)",
		// C, and prose that quotes a listed name before a parenthesis.
		"(assert)(ptr != NULL);",
		`the "system"(s) check`,
		"Type 'exec'(without quotes)",
		// Markdown: a link right after a word that starts with "$".
		"see $HOME[1](#paths)",
		// A mention or a password written like a suppressed call: at the
		// start, or after a blank or one of ";({,=.".
		" @$user(admin)",
		"please ask @$lead(team) today",
		"@$tr0ng(1)",
		"Qw.@$er(ty)",
		"k;@$Ab(1)",
		"pw(@$Ab(1)",
		"{@$Ab(1)}",
		"a,@$Bc(d)",
		"x=@$Ab(1)",
		"line one\n@$Ab(1)",
		// After any other byte, with a quote or a variable after the "(".
		"!@$Ab('c",
		"#@$Ab($cd",
		// An indexed name takes any argument wherever the "@" stands.
		"!@$Ab[1](2)",
		"#@$Ab{1}(x)",
		// "$$name" and "${" keep their own rules.
		"!@${Ab}('c')",
		"P@${ss}(1);",
		"P@$$w0rd(1);",
	)
	checkLDAPTechnique(t, true,
		// A filter pasted into a support message.
		"our filter is (&(objectClass=user)(cn=jdoe)), why is it slow?",
		"(|(mail=a@example.com)(mail=b@example.com))",
		// Code without blanks.
		"if(!(x=y)) return;",
		"mask = df[(x>0)&(y<=5)]",
		"cond = (a)|(b=1)",
		`re := "(a)|(id=\\d+)"`,
		"re = /(\\?|#)(&)/",
		// A query string with parentheses inside a text value.
		"range=(0,10)&(sort=asc)",
	)
}

// TestInjectionTechniqueAcceptedMisses pins what the three checks do not
// read; docs/threat-model.md lists it.
func TestInjectionTechniqueAcceptedMisses(t *testing.T) {
	checkPerl(t, false,
		"@{ \n[x]}",
		"@{\\(x)}",
		// Read as a PowerShell typed key or a LaTeX column.
		"@{[x]y}",
		"@{[}x]}",
	)
	checkPHPCall(t, false,
		// The narrowings: a name after a word, a plain path and "${", member
		// access, a LaTeX-like subscript, a numeric argument.
		"trim(system)('x')",
		"strval('system')(base64_decode(c))",
		"x@$f(1)",
		"!@$f(1)",
		"if($a)@$f(1)",
		"$a&&@$f(base64_decode(x));",
		"!@$_f(x);",
		"${f}(${a})",
		"${f}(${a});",
		"x.$$f('a')",
		"x.$a['b']('c')",
		"x.$_f('a')",
		"$x_{0}(1)",
		"$A[0](1)",
		"$$f(1)",
		"$_f(1)",
		"${f}(1)",
		"page.$$eval($a);",
		"$$eval($a);",
		// Spacing, comments and spelling the shapes do not read.
		"$a ('x')",
		"$a[0] (1)",
		"$a[0]# c\n(1)",
		"$a/*c*/[0](1)",
		"$a[0]/*c*/[1](1)",
		"('system') (1)",
		"('system'/*c*/)(1)",
		`('\system')(1)`,
		"('sys'.'tem')(1)",
		"['system'][0](1)",
		"[system][1](1)",
		"(system)(ls) ;",
		`(system)(f(")"));`,
		"$o->a(1)",
		"$a(1)",
		// Brackets are counted as they stand, also inside strings.
		"$a['[']('x')",
		"$a[']']('x')",
		"${'}'}('x')",
		"<? echo 1",
		"<?/**/echo 1",
	)
	checkLDAPTechnique(t, false,
		"x)(uid=admin",
		"x)(uid>=1",
		"(|(uid>=1",
		"x)( uid=*",
		"x)(uid =*",
		"x) (|(uid =1",
		"x)(1.3.6.1=*",
		"x)(cn;lang-en=*",
		"a:caseExactMatch:=b",
		"o:dn:caseIgnoreMatch:=b",
		"(|(uid=a(b",
		"x)|(a.b>=1",
	)
}

// TestInjectionTechniquesDecoded: the three rules read the value and its
// once percent-decoded form.
func TestInjectionTechniquesDecoded(t *testing.T) {
	checkDecoded := func(rule string, detect func(string) (Hit, bool), values ...string) {
		t.Helper()
		for _, v := range values {
			if h, ok := detect(v); !ok || h.RuleID != rule {
				t.Errorf("detector(%q) = %+v %v, want %s", v, h, ok, rule)
			}
			if !containsRule(ScanText(v), rule) {
				t.Errorf("ScanText(%q) lacks %s", v, rule)
			}
		}
	}
	checkDecoded("AEG-SSTI-001", SSTI, "%40%7B%5B time %5D%7D")
	checkDecoded("AEG-CODEI-001", CodeI, "%24a%5B0%5D%28x%29", "%3C%3F%20echo%201")
	checkDecoded("AEG-LDAP-001", LDAP, "u%3A1.2.3%3A%3Dx", "x%29%28uid%3D%2A", "%28%7C%28uid%3Dx")
}

// --- linear time ---

// injectionTechniqueChecks are the three checks, each with a tail it must
// find at the end of a hostile value.
var injectionTechniqueChecks = []struct {
	name  string
	match func(string) bool
	tails []string
}{
	{"perl", hasPerlInterpolation, []string{"@{[x]}"}},
	{"php", hasPHPDynamicCall, []string{
		"<? echo 1", "('system')(1)", "(system)(x);", "$a[0](1)", "$$f($a)", "${x}('a')", "$_f(x);", "@$f(1)",
	}},
	{"ldap", hasLDAPTechnique, []string{"(|(u=1", "x)(&)", "u:1.2.3:=1"}},
}

// TestInjectionTechniquesLinear: the Perl, PHP and LDAP checks stay linear
// on 1 MiB hostile values, and still find an attack at the end of one.
func TestInjectionTechniquesLinear(t *testing.T) {
	blanks := strings.Repeat(" ", 200)
	units := map[string]string{
		"perl-open":        "@{[",
		"perl-blanks":      "@{" + blanks,
		"perl-nested":      "@{[@{[",
		"perl-long":        "@{[" + strings.Repeat("a", 129),
		"perl-typed":       "@{[a]" + blanks + "'",
		"php-tag":          "<? ",
		"php-tag-blanks":   "<?" + blanks,
		"php-tag-dollars":  "<? " + strings.Repeat("$", 200) + "1",
		"php-quoted":       "x('eval')(",
		"php-plain":        "(system)(x)",
		"php-plain-open":   "(system)(",
		"php-plain-nest":   "(system)((",
		"php-semicolon":    "(system)(x) );",
		"php-after-word":   "x(system)(",
		"php-brace":        "${",
		"php-brace-close":  "${a}(",
		"php-brace-nest":   "${${a}",
		"php-brace-plain":  "${" + strings.Repeat("a", 200),
		"php-brace-arg":    "${a}(${",
		"php-brace-end":    "${a}(b) );",
		"php-template":     "${" + strings.Repeat("a?.", 70) + "a}(${",
		"php-variable":     "$$a(a",
		"php-dollars":      "$",
		"php-index":        "$a[",
		"php-index-curly":  "$a{",
		"php-index-chain":  "[0]",
		"php-index-mixed":  "$a[{$b{[",
		"php-index-empty":  "$a[]",
		"php-index-closed": "$a[0]",
		"php-comment":      "$a[0]/*",
		"php-comments":     "$a[0]/**/",
		"php-comment-in":   "$$a/*",
		"php-at":           "x@$a(",
		"php-underscore":   "$_a(a",
		"php-closers":      ")]}",
		"ldap-open":        "(",
		"ldap-or":          "(|(",
		"ldap-close":       ")(",
		"ldap-comparison":  "(|(a==",
		"ldap-code":        "(|(a=b(",
		"ldap-long-value":  "(|(a=" + strings.Repeat("b", 200) + "(",
		"ldap-attr":        ")(" + strings.Repeat("a", 200),
		"ldap-oid":         ":=",
		"ldap-oid-digits":  strings.Repeat("1.", 100) + ":=",
		"ldap-oid-attr":    strings.Repeat("a", 100) + ":1.2.3:=",
	}
	const small, medium, large = 64 << 10, 256 << 10, 1 << 20
	// A quadratic scan of 1 MiB takes tens of seconds.
	lim := wallLimit(250*time.Millisecond, 5*time.Second)
	for name, unit := range units {
		s := strings.Repeat(unit, small/len(unit))
		m := strings.Repeat(unit, medium/len(unit))
		l := strings.Repeat(unit, large/len(unit))
		for _, c := range injectionTechniqueChecks {
			if c.match(l) {
				t.Errorf("%s/%s: hit on the hostile value, want none", c.name, name)
			}
			if testing.Short() {
				continue
			}
			run := func(v string) func() { return func() { c.match(v) } }
			// The growth ratio is measured on the smaller sizes: their runs
			// are short enough to finish undisturbed on a loaded machine.
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
	for _, c := range injectionTechniqueChecks {
		for name, unit := range units {
			l := strings.Repeat(unit, large/len(unit))
			for _, end := range c.tails {
				// A line break and closers end whatever the value left open,
				// and "*/" ends an open comment.
				if !c.match(l + "\n*/ " + end) {
					t.Errorf("%s/%s: no hit with %q at the end", c.name, name, end)
				}
			}
		}
	}
}
