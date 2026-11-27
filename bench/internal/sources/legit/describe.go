package legit

import (
	"fmt"
	"maps"
	"slices"

	"github.com/ergasterion-dev/aegolith/bench/internal/cases"
)

// Description is a generated set and what it was built from.
//
// A template is one sentence pattern of a category. An entry is one string of
// one of the word lists; it fills a slot of a template or of another entry. A
// number drawn into a number slot is not an entry. Lines are combinations of
// templates and entries, so lines that share them are not independent of each
// other.
type Description struct {
	Lines []cases.Line
	// Templates, Lists and Entries are the sizes of the whole material.
	Templates, Lists, Entries int
	// TemplatesUsed and EntriesUsed count those that went into at least one
	// line, each once however many lines or categories use it.
	TemplatesUsed, EntriesUsed int
	// Categories holds one count per category of the lines, by name.
	Categories []CategoryUse
	// Cores holds one count per core list of pasted code, by name: the lists
	// whose entries are the pasted text itself.
	Cores []ListUse
}

// ListUse counts the entries of one word list: all it has, those that went
// into at least one pasted-code line, and the pasted-code lines that hold an
// entry of the list.
type ListUse struct {
	List                 string
	Entries, Used, Lines int
}

// The lists pasted code draws from, apart: coreLists hold the pasted text (an
// error message, a command, a query, a snippet and so on), framingLists the
// sentences and steps around it.
var (
	coreLists = []string{
		"code-chat", "code-config", "code-error", "code-formula", "code-html", "code-log",
		"code-markdown", "code-path", "code-path-b", "code-regex", "code-shell", "code-snippet",
		"code-sql", "code-sql-error", "code-subject", "code-template",
	}
	framingLists = []string{
		"code-config-outro", "code-expected", "code-formula-intro", "code-formula-outro",
		"code-formula-question", "code-html-intro", "code-html-outro", "code-intro", "code-log-intro",
		"code-outro", "code-path-sentence", "code-regex-intro", "code-regex-outro", "code-shell-comment",
		"code-shell-intro", "code-shell-outro", "code-shell-question", "code-snippet-intro",
		"code-sql-intro", "code-sql-outro", "code-step", "code-step-b", "code-template-intro",
		"code-template-outro",
	}
)

// CategoryUse counts the lines of one category and the templates and entries
// that went into at least one of them.
type CategoryUse struct {
	Category                            string
	Lines, NearMiss, Templates, Entries int
}

// Describe returns the lines GenerateExact gives for seed and n, with the
// counts of what they were built from.
func Describe(seed int64, n int) (Description, error) {
	return describe(material, seed, n)
}

// describe is Describe over the given categories.
func describe(categories []category, seed int64, n int) (Description, error) {
	items, _ := generate(categories, seed, n)
	if len(items) < n {
		return Description{}, fmt.Errorf("%w: seed %d gives %d distinct cases, not %d",
			ErrExhausted, seed, len(items), n)
	}
	d := Description{Lists: len(slots)}
	for _, c := range categories {
		d.Templates += len(c.templates)
	}
	for _, list := range slots {
		d.Entries += len(list)
	}

	type use struct {
		count     CategoryUse
		templates map[string]bool
		entries   map[entryRef]bool
	}
	uses := map[string]*use{}
	all := map[entryRef]bool{}
	coreUsed, coreLines := map[entryRef]bool{}, map[string]int{}
	for _, it := range items {
		d.Lines = append(d.Lines, it.line)
		name := it.line.Category
		u := uses[name]
		if u == nil {
			u = &use{count: CategoryUse{Category: name}, templates: map[string]bool{}, entries: map[entryRef]bool{}}
			uses[name] = u
		}
		u.count.Lines++
		if it.nearMiss {
			u.count.NearMiss++
		}
		u.templates[it.template] = true
		held := map[string]bool{}
		for _, e := range it.entries {
			u.entries[e], all[e] = true, true
			if name == pastedCodeCategory.name && slices.Contains(coreLists, e.list) {
				coreUsed[e], held[e.list] = true, true
			}
		}
		for list := range held {
			coreLines[list]++
		}
	}
	for _, list := range slices.Sorted(slices.Values(coreLists)) {
		core := ListUse{List: list, Entries: len(slots[list]), Lines: coreLines[list]}
		for e := range coreUsed {
			if e.list == list {
				core.Used++
			}
		}
		d.Cores = append(d.Cores, core)
	}
	for _, name := range slices.Sorted(maps.Keys(uses)) {
		u := uses[name]
		u.count.Templates, u.count.Entries = len(u.templates), len(u.entries)
		d.TemplatesUsed += u.count.Templates
		d.Categories = append(d.Categories, u.count)
	}
	d.EntriesUsed = len(all)
	return d, nil
}
