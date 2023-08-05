package securefs

import (
	"bytes"
	"encoding/gob"
	"testing"
)

func TestGob(t *testing.T) {

	gob.Register(PersistenceNode{})

	root := NewPersistenceNode(nil)

	root.AddChild("1.txt")
	c := root.AddChild("dir1")
	c.AddChild("dir2")

	var network bytes.Buffer
	enc := gob.NewEncoder(&network)
	err := enc.Encode(root)
	if err != nil {
		t.Fatal("Encode:", err)
	}

	dec := gob.NewDecoder(&network)
	root_new := &PersistenceNode{}

	err = dec.Decode(root_new)
	if err != nil {
		t.Fatal("Decode:", err)
	}

	if root.Name != root_new.Name {
		t.Fatal("root.Name not equal")
	}
	if root.parent != root_new.parent {
		t.Fatal("root.Parent not equal")
	}
	if len(root.Children) != len(root_new.Children) {
		t.Fatal("root_new.Children len not equal")
	}
	if root.Children[0].Name != root_new.Children[0].Name {
		t.Fatal("root.Children[0].Name not equal")
	}
	if root_new.Children[0].parent != root_new {
		t.Fatal("root.Children[0].Parent not equal root_new")
	}
}
