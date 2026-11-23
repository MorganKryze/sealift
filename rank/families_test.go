package rank

import (
	"reflect"
	"slices"
	"testing"
)

func TestFamiliesFromPeers(t *testing.T) {
	got := Families([]Jumper{
		{Name: "react", Current: "18.3.1", Jump: "19.2.0"},
		{Name: "react-dom", Current: "18.3.1", Jump: "19.2.0", JumpPeers: map[string]string{"react": "^19.0.0"}},
	})
	want := []Family{{Name: "react 19", Root: "react", Members: []string{"react", "react-dom"}}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Families = %+v, want %+v", got, want)
	}
}

func TestFamiliesFromTypes(t *testing.T) {
	got := Families([]Jumper{
		{Name: "@types/react", Current: "18.3.12", Jump: "19.2.2"},
		{Name: "react", Current: "18.3.1", Jump: "19.2.0"},
		{Name: "@babel/core", Current: "7.26.0", Jump: "8.0.0"},
		{Name: "@types/babel__core", Current: "7.20.5", Jump: "8.0.1"},
	})
	want := []Family{
		{Name: "@babel/core 8", Root: "@babel/core", Members: []string{"@babel/core", "@types/babel__core"}},
		{Name: "react 19", Root: "react", Members: []string{"@types/react", "react"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Families = %+v, want %+v", got, want)
	}
}

func TestFamilyNamedAfterTheMemberOthersName(t *testing.T) {
	got := Families([]Jumper{
		{Name: "zeta", Current: "0.18.2", Jump: "0.19.0"},
		{Name: "alpha-plugin", Current: "2.1.0", Jump: "3.0.0", JumpPeers: map[string]string{"zeta": "^0.19.0"}},
		{Name: "beta-plugin", Current: "1.4.0", Jump: "2.0.0", JumpPeers: map[string]string{"zeta": ">=0.19.0 <0.20.0", "alpha-plugin": "^3.0.0"}},
	})
	want := []Family{{Name: "zeta 0.19", Root: "zeta", Members: []string{"alpha-plugin", "beta-plugin", "zeta"}}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Families = %+v, want %+v", got, want)
	}
}

func TestPeerRangeThatAdmitsTheCurrentMakesNoFamily(t *testing.T) {
	got := Families([]Jumper{
		{Name: "react", Current: "18.3.1", Jump: "19.2.0"},
		{Name: "react-router-dom", Current: "6.30.0", Jump: "7.9.4", JumpPeers: map[string]string{"react": ">=18"}},
	})
	if len(got) != 0 {
		t.Errorf("Families = %+v, want none", got)
	}
}

func TestPeerRangeThatRefusesTheJumpMakesNoFamily(t *testing.T) {
	got := Families([]Jumper{
		{Name: "react", Current: "17.0.2", Jump: "19.2.0"},
		{Name: "old-widget", Current: "1.0.0", Jump: "2.0.0", JumpPeers: map[string]string{"react": "^18.0.0"}},
	})
	if len(got) != 0 {
		t.Errorf("Families = %+v, want none", got)
	}
}

func TestUnparsableRangeMakesNoEdge(t *testing.T) {
	got := Families([]Jumper{
		{Name: "react", Current: "18.3.1", Jump: "19.2.0"},
		{Name: "react-dom", Current: "18.3.1", Jump: "19.2.0", JumpPeers: map[string]string{"react": "workspace:^19"}},
	})
	if len(got) != 0 {
		t.Errorf("Families = %+v, want none", got)
	}
}

func TestLoneJumpMakesNoFamily(t *testing.T) {
	got := Families([]Jumper{
		{Name: "express", Current: "4.17.1", Jump: "5.1.0", JumpPeers: map[string]string{"react": "^19.0.0"}},
	})
	if len(got) != 0 {
		t.Errorf("Families = %+v, want none", got)
	}
	if got := Families(nil); len(got) != 0 {
		t.Errorf("Families(nil) = %+v, want none", got)
	}
}

func TestFamiliesAreDeterministic(t *testing.T) {
	jumpers := []Jumper{
		{Name: "react", Current: "18.3.1", Jump: "19.2.0"},
		{Name: "react-dom", Current: "18.3.1", Jump: "19.2.0", JumpPeers: map[string]string{"react": "^19.0.0"}},
		{Name: "@types/react", Current: "18.3.12", Jump: "19.2.2"},
		{Name: "@types/react-dom", Current: "18.3.1", Jump: "19.2.2", JumpPeers: map[string]string{"@types/react": "^19.2.0"}},
		{Name: "vue", Current: "2.7.16", Jump: "3.5.22"},
		{Name: "vue-router", Current: "3.6.5", Jump: "4.6.3", JumpPeers: map[string]string{"vue": "^3.5.0"}},
		{Name: "express", Current: "4.17.1", Jump: "5.1.0"},
	}
	want := Families(jumpers)
	if len(want) != 2 || want[0].Name != "react 19" || want[1].Name != "vue 3" {
		t.Fatalf("Families = %+v, want react 19 then vue 3", want)
	}
	for i := range 20 {
		shuffled := slices.Clone(jumpers)
		for j := range shuffled {
			k := (j*7 + i*3) % len(shuffled)
			shuffled[j], shuffled[k] = shuffled[k], shuffled[j]
		}
		if got := Families(shuffled); !reflect.DeepEqual(got, want) {
			t.Fatalf("order %d: Families = %+v, want %+v", i, got, want)
		}
	}
}
