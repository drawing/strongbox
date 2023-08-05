package securefs

import (
	"encoding/gob"
)

type PersistenceNode struct {
	Name     string
	Children []*PersistenceNode

	parent *PersistenceNode
	root   *PersistenceNode
}

func init() {
	gob.Register(PersistenceNode{})
}

func NewPersistenceNode(parent *PersistenceNode) *PersistenceNode {
	node := &PersistenceNode{}
	node.parent = parent
	return node
}

func (n *PersistenceNode) Serialization() ([]byte, error) {
	return nil, nil
}
func (n *PersistenceNode) Deserialization(b []byte) error {
	return nil
}

func (n *PersistenceNode) AddChild(name string) *PersistenceNode {
	if n.Children == nil {
		n.Children = make([]*PersistenceNode, 0)
	}
	for _, v := range n.Children {
		if v.Name == name {
			return v
		}
	}
	c := &PersistenceNode{}
	c.Name = name
	c.parent = n
	c.root = n.root
	n.Children = append(n.Children, c)
	return c
}
