package legit

import (
	"bytes"
	"maps"
	"slices"
	"strings"
	"testing"
)

// repeated builds a material in which every category of the schedule has one
// template: the category's name and the slot.
func repeated(slot string) []category {
	var out []category
	for _, c := range material {
		out = append(out, category{name: c.name, templates: []string{c.name + " " + slot}, endpoints: c.endpoints})
	}
	return out
}

// One round of the schedule over texts that name a weekday: every line of a
// category draws another weekday, so its entries are as many as its lines.
// Draws that were rejected as repeats count nowhere.
func TestDescribeCountsTemplatesAndEntries(t *testing.T) {
	t.Parallel()
	n := len(schedule)
	d, err := describe(repeated("⟦weekday⟧"), 1, n)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Lines) != n || len(d.Categories) != len(material) {
		t.Fatalf("%d lines in %d categories, want %d in %d", len(d.Lines), len(d.Categories), n, len(material))
	}
	lines := 0
	union := map[string]bool{}
	for _, l := range d.Lines {
		_, day, _ := strings.Cut(l.Payload, " ")
		union[day] = true
	}
	for i, c := range d.Categories {
		if i > 0 && c.Category <= d.Categories[i-1].Category {
			t.Errorf("categories are not sorted: %q after %q", c.Category, d.Categories[i-1].Category)
		}
		want := countOf(schedule, c.Category)
		if c.Lines != want || c.Entries != want || c.Templates != 1 || c.NearMiss != 0 {
			t.Errorf("%+v, want %d lines, %d entries, 1 template", c, want, want)
		}
		lines += c.Lines
	}
	// A weekday that several categories draw is one entry of the set.
	if lines != n || d.TemplatesUsed != len(material) || d.EntriesUsed != len(union) {
		t.Errorf("lines %d, templates used %d, entries used %d; want %d, %d, %d",
			lines, d.TemplatesUsed, d.EntriesUsed, n, len(material), len(union))
	}
}

// An entry that holds slots counts, and so does every entry that fills them.
func TestDescribeCountsNestedEntries(t *testing.T) {
	t.Parallel()
	d, err := describe(repeated("⟦email⟧"), 1, len(schedule))
	if err != nil {
		t.Fatal(err)
	}
	users, hosts := map[string]map[string]bool{}, map[string]map[string]bool{}
	for _, l := range d.Lines {
		_, address, _ := strings.Cut(l.Payload, " ")
		user, host, ok := strings.Cut(address, "@")
		if !ok {
			t.Fatalf("no address in %q", l.Payload)
		}
		if users[l.Category] == nil {
			users[l.Category], hosts[l.Category] = map[string]bool{}, map[string]bool{}
		}
		users[l.Category][user], hosts[l.Category][host] = true, true
	}
	for _, c := range d.Categories {
		// The one entry of "email", and the users and hosts drawn into it.
		if want := 1 + len(users[c.Category]) + len(hosts[c.Category]); c.Entries != want {
			t.Errorf("%s: %d entries, want %d", c.Category, c.Entries, want)
		}
	}
}

func TestDescribeTheMaterial(t *testing.T) {
	t.Parallel()
	const n = 400
	d, err := Describe(1, n)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encode(t, d.Lines), encode(t, Generate(1, n))) {
		t.Error("Describe gives other lines than Generate")
	}
	templates, entries := 0, 0
	for _, c := range material {
		templates += len(c.templates)
	}
	for _, list := range slots {
		entries += len(list)
	}
	if d.Templates != templates || d.Lists != len(slots) || d.Entries != entries {
		t.Errorf("material of %d templates, %d lists, %d entries; want %d, %d, %d",
			d.Templates, d.Lists, d.Entries, templates, len(slots), entries)
	}
	lines, used, sum, nearMiss, wantNearMiss := 0, 0, 0, 0, 0
	for _, c := range d.Categories {
		if c.Templates < 1 || c.Templates > c.Lines || c.Entries < 1 {
			t.Errorf("%+v", c)
		}
		lines, used, sum, nearMiss = lines+c.Lines, used+c.Templates, sum+c.Entries, nearMiss+c.NearMiss
	}
	for _, l := range d.Lines {
		if l.Expected != "legit" {
			wantNearMiss++
		}
	}
	if lines != n || used != d.TemplatesUsed || nearMiss != wantNearMiss {
		t.Errorf("lines %d, templates %d, near-miss %d; want %d, %d, %d",
			lines, used, nearMiss, n, d.TemplatesUsed, wantNearMiss)
	}
	if d.EntriesUsed < 1 || d.EntriesUsed > sum || d.EntriesUsed > d.Entries {
		t.Errorf("%d entries used, %d over the categories, %d in the material", d.EntriesUsed, sum, d.Entries)
	}
	if _, err := Describe(1, 5_000_000); err == nil {
		t.Error("a set larger than the material was described")
	}
}

// reachable returns the lists the templates of a category can draw from.
func reachable(c category) map[string]bool {
	out := map[string]bool{}
	var walk func(text string)
	walk = func(text string) {
		for {
			_, after, found := strings.Cut(text, slotOpen)
			if !found {
				return
			}
			name, rest, _ := strings.Cut(after, slotClose)
			text = rest
			list, ok := slots[name]
			if !ok || out[name] {
				continue
			}
			out[name] = true
			for _, entry := range list {
				walk(entry)
			}
		}
	}
	for _, t := range c.templates {
		walk(t)
	}
	return out
}

// Every list pasted code draws from either holds pasted text or the words
// around it, so that no core list can be left out of the count unnoticed.
func TestCoreListsCoverPastedCode(t *testing.T) {
	t.Parallel()
	got := slices.Sorted(maps.Keys(reachable(pastedCodeCategory)))
	want := slices.Sorted(slices.Values(slices.Concat(coreLists, framingLists)))
	if !slices.Equal(got, want) {
		t.Errorf("pasted code draws from %v;\ncore and framing lists are %v", got, want)
	}
}

func TestDescribeTheCores(t *testing.T) {
	t.Parallel()
	const n = 400
	d, err := Describe(1, n)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Cores) != len(coreLists) {
		t.Fatalf("%d core lists, want %d", len(d.Cores), len(coreLists))
	}
	items, _ := generate(material, 1, n)
	for i, core := range d.Cores {
		if i > 0 && core.List <= d.Cores[i-1].List {
			t.Errorf("core lists are not sorted: %q after %q", core.List, d.Cores[i-1].List)
		}
		used, lines := map[int]bool{}, 0
		for _, it := range items {
			found := false
			for _, e := range it.entries {
				if e.list == core.List && it.line.Category == pastedCodeCategory.name {
					used[e.index], found = true, true
				}
			}
			if found {
				lines++
			}
		}
		if core.Entries != len(slots[core.List]) || core.Used != len(used) || core.Lines != lines {
			t.Errorf("%+v, want %d entries, %d used, %d lines", core, len(slots[core.List]), len(used), lines)
		}
	}
}
