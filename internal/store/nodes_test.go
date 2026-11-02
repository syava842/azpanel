package store

import (
	"errors"
	"testing"
)

func TestNodesAndGroups(t *testing.T) {
	s := open(t)
	list, err := s.Nodes(ctx)
	if err != nil || len(list) != 1 || list[0].ID != LocalNode || !list[0].Connected() {
		t.Fatalf("после миграции: %+v %v", list, err)
	}
	id, err := s.AddNode(ctx, NodeRec{Name: "n2", Token: "tok", Created: 5})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddNode(ctx, NodeRec{Name: "n2"}); !errors.Is(err, ErrNodeExists) {
		t.Fatalf("повторное имя: %v", err)
	}
	n, ok, _ := s.NodeByID(ctx, id)
	if !ok || n.Connected() || n.Kind != KindNode || n.Token != "tok" {
		t.Fatalf("новый узел: %+v", n)
	}
	if err := s.SetNodeConn(ctx, id, "https://h:9100", "ab"); err != nil {
		t.Fatal(err)
	}
	if n, _, _ = s.NodeByID(ctx, id); !n.Connected() || n.URL != "https://h:9100" {
		t.Fatalf("после подключения: %+v", n)
	}
	gid, err := s.AddGroup(ctx, "g", LocalNode, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddGroup(ctx, "g2", LocalNode, 1); err == nil {
		t.Fatal("узел уже в группе, а вторая группа создана")
	}
	if err := s.SetNodeGroup(ctx, id, gid, RoleReplica); err != nil {
		t.Fatal(err)
	}
	if n, _, _ = s.NodeByID(ctx, id); n.GroupID != gid || n.Role != RoleReplica {
		t.Fatalf("реплика: %+v", n)
	}
	if err := s.DeleteGroup(ctx, gid); err != nil {
		t.Fatal(err)
	}
	if n, _, _ = s.NodeByID(ctx, id); n.GroupID != 0 || n.Role != "" {
		t.Fatalf("после удаления группы: %+v", n)
	}
	if err := s.DeleteNode(ctx, LocalNode); !errors.Is(err, ErrNodeLocal) {
		t.Fatalf("локальный: %v", err)
	}
	if err := s.AddTraffic(ctx, id, 60, map[string]Bytes{"a": {Rx: 1}}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteNode(ctx, id); err != nil {
		t.Fatal(err)
	}
	if list, _ = s.Nodes(ctx); len(list) != 1 {
		t.Fatalf("узел не удалён: %+v", list)
	}
}
