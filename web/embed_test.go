package web

import (
	"io/fs"
	"testing"
)

func TestImportScreensNeverShowTheCollection(t *testing.T) {
	screens, err := ImportScreens()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Stat(screens, "index.html"); err != nil {
		t.Errorf("the import screens have no index.html: %v", err)
	}
	for _, name := range []string{"app/index.html", "dist/app/index.html"} {
		if _, err := fs.Stat(screens, name); err == nil {
			t.Errorf("the import screens expose %s", name)
		}
	}
}
