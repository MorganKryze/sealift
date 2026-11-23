package rank

import (
	"cmp"
	"slices"
	"strings"

	"github.com/Masterminds/semver/v3"
)

// Jumper is a dependency with a jump: its current version, the version
// outside its line it could move to, and that version's peerDependencies.
type Jumper struct {
	Name, Current, Jump string
	JumpPeers           map[string]string
}

// Family is a group of dependencies whose jumps must move together.
type Family struct {
	Name    string // the root and the line of its jump, such as "react 19"
	Root    string
	Members []string // sorted
}

// Families groups jumpers that cannot jump without each other. B joins A
// when B's jump declares a peer range on A that excludes A's current
// version and admits A's jump, or when B is A's @types package. It returns
// the groups of two or more, sorted by name.
func Families(jumpers []Jumper) []Family {
	byName := make(map[string]Jumper, len(jumpers))
	names := make([]string, 0, len(jumpers))
	for _, j := range jumpers {
		if _, seen := byName[j.Name]; !seen {
			names = append(names, j.Name)
		}
		byName[j.Name] = j
	}
	slices.Sort(names)

	parent := make(map[string]string, len(names))
	var find func(string) string
	find = func(n string) string {
		if p := parent[n]; p != "" && p != n {
			parent[n] = find(p)
			return parent[n]
		}
		return n
	}
	namedBy := make(map[string]int, len(names))
	for _, b := range names {
		for _, a := range names {
			if a == b || !needs(byName[b], byName[a]) {
				continue
			}
			namedBy[a]++
			ra, rb := find(a), find(b)
			if ra != rb {
				parent[max(ra, rb)] = min(ra, rb)
			}
		}
	}

	groups := make(map[string][]string)
	for _, n := range names {
		r := find(n)
		groups[r] = append(groups[r], n)
	}
	var families []Family
	for _, members := range groups {
		if len(members) < 2 {
			continue
		}
		root := slices.MaxFunc(members, func(a, b string) int {
			return cmp.Or(cmp.Compare(namedBy[a], namedBy[b]), strings.Compare(b, a))
		})
		families = append(families, Family{
			Name:    root + " " + LineOf(byName[root].Jump),
			Root:    root,
			Members: members,
		})
	}
	slices.SortFunc(families, func(a, b Family) int {
		return cmp.Or(strings.Compare(a.Name, b.Name), strings.Compare(a.Root, b.Root))
	})
	return families
}

// needs reports whether b cannot jump without a.
func needs(b, a Jumper) bool {
	if b.Name == "@types/"+typesName(a.Name) {
		return true
	}
	r, ok := b.JumpPeers[a.Name]
	if !ok {
		return false
	}
	c, err := semver.NewConstraint(r)
	if err != nil {
		return false
	}
	current, errC := semver.StrictNewVersion(a.Current)
	jump, errJ := semver.StrictNewVersion(a.Jump)
	return errC == nil && errJ == nil && !c.Check(current) && c.Check(jump)
}

// typesName is the name DefinitelyTyped gives a package: @babel/core
// becomes babel__core.
func typesName(name string) string {
	return strings.Replace(strings.TrimPrefix(name, "@"), "/", "__", 1)
}
