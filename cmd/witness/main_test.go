package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"witness/internal/charter"
	"witness/internal/diag"
	"witness/internal/strictjson"
)

func TestCharterCLIInitFreezeAmendShow(t *testing.T) {
	dir := t.TempDir()
	charterPath := filepath.Join(dir, "charter.json")
	showPath := filepath.Join(dir, "show.json")
	freezePath := filepath.Join(dir, "freeze.json")
	amendedFreezePath := filepath.Join(dir, "freeze-amended.json")
	amendmentsPath := filepath.Join(dir, "amendments.jsonl")
	eventPath := filepath.Join(dir, "event.json")

	if err := route([]string{"charter", "init", "-out", charterPath, "-actor", "owner"}); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := route([]string{"charter", "show", "-charter", charterPath, "-out", showPath}); err != nil {
		t.Fatalf("show: %v", err)
	}
	showData, err := os.ReadFile(showPath)
	if err != nil {
		t.Fatal(err)
	}
	normalized, err := strictjson.DecodeBytes[charter.NormalizedCharter](showData, strictjson.DefaultMaxBytes)
	if err != nil {
		t.Fatalf("decode show output: %v", err)
	}
	if len(normalized.StandingNoGoals) != 1 || normalized.StandingNoGoals[0].Statement != charter.StandingNoGoalsStatement {
		t.Fatalf("standing invariant = %#v", normalized.StandingNoGoals)
	}

	if err := route([]string{"charter", "freeze", "-charter", charterPath, "-out", freezePath}); err != nil {
		t.Fatalf("freeze: %v", err)
	}
	before := readFrozen(t, freezePath)

	eventJSON := []byte(`{"id":"event-2","type":"charter_amended","actor":"owner","summary":"Append owner amendment."}`)
	if err := os.WriteFile(eventPath, eventJSON, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := route([]string{"charter", "amend", "-charter", charterPath, "-amendments", amendmentsPath, "-event", eventPath, "-out", amendedFreezePath}); err != nil {
		t.Fatalf("amend: %v", err)
	}
	after := readFrozen(t, amendedFreezePath)
	if before.CharterHash == after.CharterHash {
		t.Fatalf("amended hash did not change: %s", before.CharterHash)
	}
	amendments, err := charter.ReadAmendmentsFile(amendmentsPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(amendments) != 1 || amendments[0].ID != "event-2" {
		t.Fatalf("amendments = %#v", amendments)
	}
}

func TestCharterAmendRejectsOutputAliasingAmendments(t *testing.T) {
	dir := t.TempDir()
	charterPath := filepath.Join(dir, "charter.json")
	amendmentsPath := filepath.Join(dir, "amendments.jsonl")
	eventPath := filepath.Join(dir, "event.json")

	if err := route([]string{"charter", "init", "-out", charterPath, "-actor", "owner"}); err != nil {
		t.Fatalf("init: %v", err)
	}
	originalLedger := []byte(`{"actor":"owner","id":"event-2","summary":"Existing amendment.","type":"charter_amended"}` + "\n")
	if err := os.WriteFile(amendmentsPath, originalLedger, 0o644); err != nil {
		t.Fatal(err)
	}
	eventJSON := []byte(`{"id":"event-3","type":"charter_amended","actor":"owner","summary":"Append owner amendment."}`)
	if err := os.WriteFile(eventPath, eventJSON, 0o644); err != nil {
		t.Fatal(err)
	}

	err := route([]string{"charter", "amend", "-charter", charterPath, "-amendments", amendmentsPath, "-event", eventPath, "-out", amendmentsPath})
	if err == nil {
		t.Fatal("amend succeeded, want output path conflict")
	}
	if got := diag.FromError(err).Code; got != charter.CodeOutputPathConflict {
		t.Fatalf("diagnostic code = %s, want %s; err=%v", got, charter.CodeOutputPathConflict, err)
	}
	afterLedger, err := os.ReadFile(amendmentsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(afterLedger, originalLedger) {
		t.Fatalf("ledger changed:\nafter: %s\nwant:  %s", afterLedger, originalLedger)
	}
}

func TestRejectOutputPathAliasesRejectsHardLinkedAmendments(t *testing.T) {
	dir := t.TempDir()
	amendmentsPath := filepath.Join(dir, "amendments.jsonl")
	outputPath := filepath.Join(dir, "output.json")

	if err := os.WriteFile(amendmentsPath, []byte("existing ledger\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(amendmentsPath, outputPath); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}

	err := rejectOutputPathAliases(outputPath, protectedInput{role: "amendments", path: amendmentsPath})
	assertOutputPathConflict(t, err)
}

func TestRejectOutputPathAliasesRejectsDanglingSymlinkToAmendments(t *testing.T) {
	dir := t.TempDir()
	amendmentsPath := filepath.Join(dir, "amendments.jsonl")
	outputPath := filepath.Join(dir, "output.json")

	if err := os.Symlink(filepath.Base(amendmentsPath), outputPath); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
		t.Fatalf("output symlink is not dangling: %v", err)
	}

	err := rejectOutputPathAliases(outputPath, protectedInput{role: "amendments", path: amendmentsPath})
	assertOutputPathConflict(t, err)
}

func assertOutputPathConflict(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("alias check succeeded, want output path conflict")
	}
	if got := diag.FromError(err).Code; got != charter.CodeOutputPathConflict {
		t.Fatalf("diagnostic code = %s, want %s; err=%v", got, charter.CodeOutputPathConflict, err)
	}
}

func readFrozen(t *testing.T, path string) charter.FrozenCharter {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	frozen, err := strictjson.DecodeBytes[charter.FrozenCharter](data, strictjson.DefaultMaxBytes)
	if err != nil {
		t.Fatalf("decode frozen charter: %v", err)
	}
	return frozen
}
