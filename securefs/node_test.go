package securefs

import (
	"encoding/json"
	"testing"
)

func TestJsonUnmarshal(t *testing.T) {

	root := &BoxInode{}
	root.Name = "Test Root"

	root.AddChildNode("1.txt")
	c := root.AddChildNode("dir1")
	c.AddChildNode("dir2")

	data, err := json.Marshal(root)

	root_new := &BoxInode{}
	err = json.Unmarshal(data, root_new)
	if err != nil {
		t.Fatal("Decode:", err)
	}

	if root.Name != root_new.Name {
		t.Fatal("root.Name not equal")
	}
	if root.parent != root_new.parent {
		t.Fatal("root.Parent not equal")
	}
	if len(root.ChildrenNode) != len(root_new.ChildrenNode) {
		t.Fatal("root_new.Children len not equal")
	}
}
