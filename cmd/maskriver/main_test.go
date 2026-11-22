package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/haoyuehx/maskriver/pkg/contracts"
)

// reviewProvisioning is the deployment shape the review commands need: one
// synthetic reviewer key file, the trust file naming its public key, and the
// decision store directory. Everything lives under a test temp dir, and the
// private key never leaves this struct.
type reviewProvisioning struct {
	historyDir, trustFile, reviewerKeyFile string
	private                                ed25519.PrivateKey
}

// newReviewProvisioning generates a synthetic reviewer key and trust file.
func newReviewProvisioning(t *testing.T) reviewProvisioning {
	t.Helper()
	return newReviewProvisioningWithSeed(t, 0x0c)
}

// newReviewProvisioningWithSeed generates a distinct synthetic reviewer so a
// test can hold an "attacker" key that is not the deployment trust key.
func newReviewProvisioningWithSeed(t *testing.T, seed byte) reviewProvisioning {
	t.Helper()
	dir := t.TempDir()
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
	public, ok := private.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("ed25519 private key did not expose a public key")
	}
	provisioning := reviewProvisioning{
		historyDir:      filepath.Join(dir, "history"),
		trustFile:       filepath.Join(dir, "trust.json"),
		reviewerKeyFile: filepath.Join(dir, "reviewer.key"),
		private:         private,
	}
	if err := os.WriteFile(provisioning.reviewerKeyFile, private, 0o600); err != nil {
		t.Fatal(err)
	}
	trust := fmt.Sprintf(`{"version":"maskriver-trust-v1","keys":[{"signer_key_id":"reviewer-1","public_key_hex":"%s"}]}`,
		hex.EncodeToString(public))
	if err := os.WriteFile(provisioning.trustFile, []byte(trust), 0o600); err != nil {
		t.Fatal(err)
	}
	return provisioning
}

// reviewFlags returns the flags the approve and revoke commands need.
func (p reviewProvisioning) reviewFlags() []string {
	return []string{
		"--history-dir", p.historyDir, "--trust-file", p.trustFile,
		"--reviewer-key-id", "reviewer-1", "--reviewer-key-file", p.reviewerKeyFile,
	}
}

// applyFlags returns the flags an authorized apply needs: the read-only store and
// the deployment trust file, never a reviewer private key.
func (p reviewProvisioning) applyFlags() []string {
	return []string{"--history-dir", p.historyDir, "--trust-file", p.trustFile}
}

// issueApproval runs the approve command for one declared plan. A masking
// --key-file is dropped on purpose: issuing a decision must not need the masking
// key, and the approve command takes no such flag.
func (p reviewProvisioning) issueApproval(t *testing.T, base []string) []string {
	t.Helper()
	planFlags := make([]string, 0, len(base))
	for index := 0; index < len(base); index++ {
		if base[index] == "--key-file" {
			index++
			continue
		}
		planFlags = append(planFlags, base[index])
	}
	args := append([]string{"approve"}, planFlags...)
	args = append(args, p.reviewFlags()...)
	args = append(args, "--reviewer-id", "reviewer@synthetic.example")
	var out, errOut bytes.Buffer
	if code := run(args, &out, &errOut); code != 0 {
		t.Fatalf("approve exit=%d, want 0; output=%q", code, out.String()+errOut.String())
	}
	return args
}

// cliExec runs synthetic DDL/DML against one disposable CLI fixture file.
func cliExec(t *testing.T, path string, statements ...string) {
	t.Helper()
	database, err := sql.Open("sqlite", "file:"+path+"?mode=rwc&_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range statements {
		if _, err = database.Exec(statement); err != nil {
			_ = database.Close()
			t.Fatalf("fixture statement failed: %v", err)
		}
	}
	if err = database.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCLIArguments(t *testing.T) {
	tests := []struct {
		name string
		args []string
		code int
		text string
	}{
		{"help", nil, 0, "SQLite"},
		{"explicit help", []string{"--help"}, 0, "Usage:"},
		{"version", []string{"--version"}, 0, version},
		{"scan missing paths", []string{"scan"}, 2, "operation refused"},
		{"mask missing paths", []string{"mask"}, 2, "operation refused"},
		{"apply missing paths", []string{"mask", "--apply"}, 2, "operation refused"},
		{"validate missing paths", []string{"validate"}, 2, "operation refused"},
		{"command help", []string{"mask", "--help"}, 0, "Usage:"},
		{"help command", []string{"help", "scan"}, 0, "Usage: maskriver scan"},
		{"help status", []string{"help", "status"}, 0, "Usage: maskriver status"},
		{"help version", []string{"help", "version"}, 0, "Usage: maskriver version"},
		{"help extra", []string{"help", "mask", "extra"}, 2, "invalid arguments"},
		{"help unknown", []string{"help", "nope"}, 2, "invalid arguments"},
		{"unknown", []string{"unknown"}, 2, "invalid arguments"},
		{"unknown flag", []string{"mask", "--unknown"}, 2, "invalid arguments"},
		{"positional rejected", []string{"mask", "unexpected"}, 2, "invalid arguments"},
		{"scan apply rejected", []string{"scan", "--apply"}, 2, "invalid arguments"},
		{"scan scope without paths", []string{"scan", "--scope", "people.email"}, 2, "operation refused"},
		{"scope without separator", []string{"scan", "--scope", "people"}, 2, "invalid arguments"},
		{"scope empty column", []string{"mask", "--scope", "people."}, 2, "invalid arguments"},
		{"scope empty table", []string{"validate", "--scope", ".email"}, 2, "invalid arguments"},
		{"scope extra separator", []string{"mask", "--scope", "a.b.c"}, 2, "invalid arguments"},
		{"extra version args", []string{"version", "extra"}, 2, "invalid arguments"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			if got := run(tt.args, &out, &errOut); got != tt.code {
				t.Fatalf("exit=%d, want %d", got, tt.code)
			}
			if !strings.Contains(out.String()+errOut.String(), tt.text) {
				t.Fatalf("missing %q in safe output", tt.text)
			}
		})
	}
}

func TestCLIFlagParseErrorsAreSanitized(t *testing.T) {
	const marker = "SYNTHETIC-DSN-DO-NOT-ECHO"
	tests := []struct {
		name string
		args []string
	}{
		{"workers integer", []string{"mask", "--workers", marker}},
		{"min samples integer", []string{"scan", "--source", marker, "--min-samples", marker}},
		{"sample limit integer", []string{"scan", "--sample-limit=" + marker}},
		{"batch size integer", []string{"mask", "--target", marker, "--batch-size=" + marker}},
		{"min ratio float", []string{"scan", "--min-ratio", marker}},
		{"approved bool", []string{"validate", "--key-file", marker, "--approved=" + marker}},
		{"apply bool", []string{"mask", "--source=" + marker, "--apply=" + marker}},
		{"strict bool", []string{"validate", "--strict=" + marker}},
		{"scope format", []string{"scan", "--scope", marker}},
		{"unknown flag name", []string{"mask", "--" + marker}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			if code := run(tt.args, &out, &errOut); code != 2 {
				t.Fatalf("exit=%d, want 2", code)
			}
			for streamName, stream := range map[string]string{"stdout": out.String(), "stderr": errOut.String()} {
				if strings.Contains(stream, marker) {
					t.Fatalf("synthetic marker leaked to %s: %q", streamName, stream)
				}
			}
			if !strings.Contains(errOut.String(), "invalid arguments") {
				t.Fatalf("missing sanitized parse error: %q", errOut.String())
			}
			// The upstream flag package wording also embeds user-supplied values.
			for _, leaked := range []string{"invalid value", "parse error", "flag provided but not defined"} {
				if strings.Contains(errOut.String(), leaked) {
					t.Fatalf("raw flag parser detail %q reached stderr: %q", leaked, errOut.String())
				}
			}
			if out.Len() != 0 {
				t.Fatalf("parse failure wrote to stdout: %q", out.String())
			}
		})
	}
}

func TestCLIHelpPrintsCompleteStaticFlags(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{"mask long help", []string{"mask", "--help"}, []string{"Usage: maskriver mask [flags]", "-source", "-target", "-scope", "-workers", "-batch-size", "-strategy", "-key-file", "-approved", "-apply", "-trust-file", "-history-dir"}},
		{"mask short help", []string{"mask", "-h"}, []string{"Usage: maskriver mask [flags]", "-source", "-target", "-scope", "-workers", "-batch-size", "-key-file", "-approved", "-apply", "-trust-file", "-history-dir"}},
		{"validate help", []string{"validate", "--help"}, []string{"Usage: maskriver validate [flags]", "-source", "-target", "-scope", "-strict", "-format"}},
		{"approve help", []string{"approve", "--help"}, []string{"Usage: maskriver approve [flags]", "-scope", "-trust-file", "-history-dir", "-reviewer-key-id", "-reviewer-key-file", "-reviewer-id", "-valid-for"}},
		{"revoke help", []string{"revoke", "--help"}, []string{"Usage: maskriver revoke [flags]", "-scope", "-trust-file", "-history-dir", "-reviewer-key-file"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			if code := run(tt.args, &out, &errOut); code != 0 {
				t.Fatalf("exit=%d, want 0", code)
			}
			text := out.String() + errOut.String()
			for _, item := range tt.want {
				if !strings.Contains(text, item) {
					t.Errorf("help missing %q", item)
				}
			}
			if out.Len() != 0 {
				t.Errorf("help wrote to stdout: %q", out.String())
			}
			// Help must be emitted once: the parse-time banner is discarded.
			if n := strings.Count(text, tt.want[0]); n != 1 {
				t.Errorf("usage banner printed %d times, want 1: %q", n, text)
			}
		})
	}
}

func TestCLIRealSQLiteWorkflow(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source.db")
	target := filepath.Join(dir, "target.db")
	keyFile := filepath.Join(dir, "key.bin")
	// The planned column must not be UNIQUE. Since work package B2b-1 the write
	// preflight refuses to mask a column that a UNIQUE constraint could collide
	// on (internal/runner/execute.go, checkTableCapabilities), so the shared
	// testenv.Seed fixture, whose people.email is UNIQUE, can no longer be the
	// CLI end-to-end input. This local fixture keeps the same workflow coverage
	// with a UNIQUE column that is not planned, a plain index on the planned
	// column, and a CHECK on an unrelated column.
	cliExec(t, source,
		`CREATE TABLE people (id INTEGER PRIMARY KEY, email TEXT NOT NULL, handle TEXT NOT NULL UNIQUE, nickname TEXT NULL, CHECK (id > 0))`,
		`CREATE INDEX people_email ON people(email)`,
	)
	seed, err := sql.Open("sqlite", "file:"+source+"?mode=rw")
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 25; i++ {
		var nickname any
		if i > 1 {
			// One NULL nickname keeps a nullable non-planned column in the schema.
			nickname = fmt.Sprintf("synthetic-%02d", i)
		}
		if _, err = seed.Exec(`INSERT INTO people(id,email,handle,nickname) VALUES(?,?,?,?)`,
			i, fmt.Sprintf("fixture-%02d@example.invalid", i), fmt.Sprintf("handle-%02d", i), nickname); err != nil {
			t.Fatal("seed fixture failed", err)
		}
	}
	if err = seed.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, before, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, []byte(strings.Repeat("K", 40)), 0600); err != nil {
		t.Fatal(err)
	}
	base := []string{"--source", source, "--target", target,
		"--table", "people", "--column", "email"}
	// Work package C2: an explicit apply also needs an authenticated reviewer
	// decision bound to this plan. The reviewer key and trust file are
	// synthetic and generated for this test.
	review := newReviewProvisioning(t)
	runCmd := func(code int, command string, extras ...string) string {
		t.Helper()
		args := append([]string{command}, base...)
		args = append(args, extras...)
		var out, errOut bytes.Buffer
		if got := run(args, &out, &errOut); got != code {
			t.Fatalf("%s exit=%d wanted=%d; sanitized output=%s", command, got, code, errOut.String())
		}
		all := out.String() + errOut.String()
		if strings.Contains(all, "fixture-01@example.invalid") ||
			strings.Contains(all, strings.Repeat("K", 40)) ||
			strings.Contains(all, source) || strings.Contains(all, target) ||
			strings.Contains(all, review.historyDir) || strings.Contains(all, review.trustFile) ||
			strings.Contains(all, review.reviewerKeyFile) {
			t.Fatal("CLI leaked secret or path")
		}
		return all
	}
	scan := runCmd(0, "scan")
	if !strings.Contains(scan, "complete=true") {
		t.Fatal("scan did not recognize synthetic email samples")
	}
	common := []string{"--strategy", "fake_email", "--key-id", "synthetic-key", "--key-file", keyFile}
	runCmd(2, "mask", append(append([]string{}, common...), "--apply")...)
	// The pre-C2 bypass is gone: --approved --apply without a stored decision is
	// refused, and so is --apply --approved without the trust flags.
	runCmd(2, "mask", append(append([]string{}, common...), "--apply", "--approved")...)
	beforeTarget, _ := os.ReadFile(target)
	if got := runCmd(0, "mask", common...); !strings.Contains(got, "dry-run=true") {
		t.Fatal("preview was not read-only")
	}
	afterPreview, _ := os.ReadFile(target)
	if sha256.Sum256(beforeTarget) != sha256.Sum256(afterPreview) {
		t.Fatal("dry run changed target file")
	}
	// Without a decision the authorized-looking invocation is still refused.
	runCmd(1, "mask", append(append(append([]string{}, common...), review.applyFlags()...), "--apply", "--approved")...)
	review.issueApproval(t, append(append([]string{}, base...), common...))
	if got := runCmd(0, "mask", append(append(append([]string{}, common...), review.applyFlags()...), "--apply", "--approved")...); !strings.Contains(got, "complete=true") {
		t.Fatal("authorized apply incomplete")
	}
	afterSource, _ := os.ReadFile(source)
	if sha256.Sum256(before) != sha256.Sum256(afterSource) {
		t.Fatal("source snapshot changed after apply")
	}
	result := runCmd(0, "validate", append(append([]string{}, common...), "--approved", "--strict")...)
	if !strings.Contains(result, "pass=true") {
		t.Fatal("strict post-write validation failed")
	}
	query, err := sql.Open("sqlite", "file:"+target+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer query.Close()
	var distinct, total int
	if err := query.QueryRow("SELECT COUNT(DISTINCT email), COUNT(*) FROM people").Scan(&distinct, &total); err != nil {
		t.Fatal(err)
	}
	if distinct != 25 || total != 25 {
		t.Fatal("unique email constraint or row count was not preserved")
	}
	if err := query.Close(); err != nil {
		t.Fatal(err)
	}
	serialMasked, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, before, 0600); err != nil {
		t.Fatal(err)
	}
	parallel := append(append([]string{}, common...), "--workers", "4")
	runCmd(0, "mask", parallel...)
	runCmd(0, "mask", append(append(append([]string{}, parallel...), review.applyFlags()...), "--apply", "--approved")...)
	runCmd(0, "validate", append(append([]string{}, parallel...), "--approved", "--strict")...)
	parallelMasked, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(serialMasked) != sha256.Sum256(parallelMasked) {
		t.Fatal("serial and parallel mask runs differ on durable SQLite results")
	}
	// Re-running Apply would try to mask already-modified data; must refuse even
	// though the decision is still valid.
	runCmd(1, "mask", append(append(append([]string{}, common...), review.applyFlags()...), "--apply", "--approved")...)
	// Same inode is never a source + target pair.
	args := []string{"scan", "--source", source, "--target", source,
		"--table", "people", "--column", "email"}
	if got := run(args, &bytes.Buffer{}, &bytes.Buffer{}); got != 2 {
		t.Fatal("same source and target must be rejected")
	}
}

// TestCLIRefusesUniquePlannedColumn documents the intentional product limit
// introduced by work package B2b-1: masking a column that a UNIQUE constraint
// could collide on is refused before any write (see internal/runner/execute.go,
// checkTableCapabilities). The refusal must be sanitized and must leave the
// target byte-identical, for preview and for an explicit --apply alike.
func TestCLIRefusesUniquePlannedColumn(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source.db")
	target := filepath.Join(dir, "target.db")
	keyFile := filepath.Join(dir, "key.bin")
	cliExec(t, source, `CREATE TABLE people (id INTEGER PRIMARY KEY, email TEXT NOT NULL UNIQUE)`)
	seed, err := sql.Open("sqlite", "file:"+source+"?mode=rw")
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 20; i++ {
		if _, err = seed.Exec(`INSERT INTO people VALUES(?,?)`, i, fmt.Sprintf("fixture-%02d@example.invalid", i)); err != nil {
			t.Fatal("seed fixture failed", err)
		}
	}
	if err = seed.Close(); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(target, original, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(keyFile, []byte(strings.Repeat("K", 40)), 0600); err != nil {
		t.Fatal(err)
	}
	base := []string{"--source", source, "--target", target, "--table", "people", "--column", "email",
		"--min-samples", "1", "--strategy", "fake_email", "--key-id", "synthetic-key", "--key-file", keyFile}
	review := newReviewProvisioning(t)
	// The plan itself is buildable, so a decision can be issued; the write gate
	// that refuses is the UNIQUE preflight, not the approval gate.
	review.issueApproval(t, base)
	for _, extras := range [][]string{{}, append(append([]string{}, review.applyFlags()...), "--apply", "--approved")} {
		args := append(append([]string{"mask"}, base...), extras...)
		var out, errOut bytes.Buffer
		if got := run(args, &out, &errOut); got == 0 {
			t.Fatalf("%v exited 0, want a refusal", extras)
		}
		all := out.String() + errOut.String()
		// Preview refuses through fail(), an explicit --apply through its own
		// sanitized batch report; neither may name a path, key or value.
		if !strings.Contains(all, "operation refused") && !strings.Contains(all, "apply: complete=false") {
			t.Fatalf("refusal output=%q, want a sanitized refusal", all)
		}
		for _, secret := range []string{"fixture-01@example.invalid", strings.Repeat("K", 40), source, target,
			review.historyDir, review.trustFile, review.reviewerKeyFile} {
			if strings.Contains(all, secret) {
				t.Fatalf("CLI leaked %q: %q", secret, all)
			}
		}
	}
	after, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(original) != sha256.Sum256(after) {
		t.Fatal("refused CLI run changed the target copy")
	}
}

// scopePair writes identical synthetic source/target copies holding two tables
// with one sensitive column each, so a repeated -scope can be exercised end to
// end without depending on the single-table fixture seeder.
func scopePair(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	source, target := filepath.Join(dir, "source.db"), filepath.Join(dir, "target.db")
	for _, path := range []string{source, target} {
		database, err := sql.Open("sqlite", "file:"+path+"?mode=rwc")
		if err != nil {
			t.Fatal(err)
		}
		for _, statement := range []string{
			`CREATE TABLE people (id INTEGER PRIMARY KEY, email TEXT NULL)`,
			`INSERT INTO people VALUES (1, 'alpha@example.invalid'), (2, 'beta@example.invalid')`,
			`CREATE TABLE contacts (id INTEGER PRIMARY KEY, email TEXT NULL)`,
			`INSERT INTO contacts VALUES (1, 'gamma@example.invalid'), (2, 'delta@example.invalid')`,
		} {
			if _, err = database.Exec(statement); err != nil {
				_ = database.Close()
				t.Fatalf("fixture statement failed: %v", err)
			}
		}
		if err = database.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return source, target
}

// TestCLIMultiTableWorkflow is the B2b-2 end-to-end case: scan, preview, apply
// and validate really run over a two-table fixture through the CLI, the exit
// codes follow the documented 0/1/2 contract, and no output may name a path, a
// synthetic value or the key.
func TestCLIMultiTableWorkflow(t *testing.T) {
	source, target := scopePair(t)
	keyFile := filepath.Join(filepath.Dir(source), "key.bin")
	if err := os.WriteFile(keyFile, []byte(strings.Repeat("K", 40)), 0600); err != nil {
		t.Fatal(err)
	}
	sanitized := func(code int, args ...string) string {
		t.Helper()
		var out, errOut bytes.Buffer
		if got := run(args, &out, &errOut); got != code {
			t.Fatalf("%v exit=%d wanted=%d; sanitized output=%s", args, got, code, out.String()+errOut.String())
		}
		all := out.String() + errOut.String()
		for _, secret := range []string{
			"alpha@example.invalid", "beta@example.invalid",
			"gamma@example.invalid", "delta@example.invalid",
			strings.Repeat("K", 40), source, target,
		} {
			if strings.Contains(all, secret) {
				t.Fatalf("CLI leaked %q: %q", secret, all)
			}
		}
		return all
	}
	if got := sanitized(0, "scan", "--source", source, "--target", target, "--scope", "people.email", "--min-samples", "1"); !strings.Contains(got, "complete=true columns=1") {
		t.Fatalf("single scope scan output=%q", got)
	}
	// --min-samples 1 keeps detection deterministic so no assertion can pass by
	// accident through an UNKNOWN verdict.
	if got := sanitized(0, "scan", "--source", source, "--target", target,
		"--scope", "people.email", "--scope", "contacts.email", "--min-samples", "1"); !strings.Contains(got, "complete=true columns=2") {
		t.Fatalf("repeated scope scan output=%q", got)
	}
	common := []string{"--strategy", "fake_email", "--key-id", "synthetic-key", "--key-file", keyFile}
	twoScopes := []string{"--scope", "people.email", "--scope", "contacts.email", "--min-samples", "1"}
	// A two-table plan is approved as a whole; the decision binds both tables in
	// declared order.
	review := newReviewProvisioning(t)
	review.issueApproval(t, append(append([]string{"--source", source, "--target", target}, common...), twoScopes...))
	previewArgs := append(append([]string{"mask", "--source", source, "--target", target}, common...), twoScopes...)
	beforeApply, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if got := sanitized(0, previewArgs...); !strings.Contains(got, "preview: dry-run=true") {
		t.Fatalf("multi-scope preview output=%q", got)
	}
	afterPreview, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(beforeApply) != sha256.Sum256(afterPreview) {
		t.Fatal("multi-scope preview changed the target copy")
	}
	validateArgs := append(append([]string{"validate", "--source", source, "--target", target}, common...), twoScopes...)
	// Both tables are still unmasked, so strict validation can not pass yet.
	sanitized(1, validateArgs...)
	applyArgs := append(append(append([]string{}, previewArgs...), review.applyFlags()...), "--approved", "--apply")
	applied := sanitized(0, applyArgs...)
	// Default batch size 64 covers each two-row table in one batch, so the
	// summary must show one committed batch and two rows per table position.
	for _, want := range []string{
		"apply: complete=true committed_batches=2 committed_rows=4 outcome_unknown=false",
		"apply: table 1 batches=1 rows=2",
		"apply: table 2 batches=1 rows=2",
	} {
		if !strings.Contains(applied, want) {
			t.Fatalf("apply summary missing %q: %q", want, applied)
		}
	}
	if got := sanitized(0, append(append([]string{}, validateArgs...), "--approved", "--strict")...); !strings.Contains(got, "pass=true") {
		t.Fatalf("strict post-write validation output=%q", got)
	}
	// A second apply would mask already-masked rows: the dry run refuses it.
	sanitized(1, applyArgs...)
	sanitized(2, "scan", "--source", source, "--target", target, "--scope", "people.email", "--table", "people")
	sanitized(2, "scan", "--source", source, "--target", target, "--scope", "people.email", "--column", "email")
	sanitized(2, "scan", "--source", source, "--target", target, "--scope", "people.email", "--scope", "people.email")
}

// TestCLIApplySummaryIsSanitized pins the failure summary the CLI prints for an
// incomplete or unknown-outcome apply: table positions and counts only, with
// complete=false and outcome_unknown, and nothing that could name a table, a
// value, a key or a path.
func TestCLIApplySummaryIsSanitized(t *testing.T) {
	plan := contracts.Plan{Tables: []contracts.TablePlan{
		{Table: contracts.TableRef{Database: "maskriver", Schema: "main", Table: "people"}},
		{Table: contracts.TableRef{Database: "maskriver", Schema: "main", Table: "contacts"}},
	}}
	report := contracts.ApplyReport{
		Committed: []contracts.BatchReceipt{
			{Table: plan.Tables[0].Table, Ordinal: 1, Rows: 2},
			{Table: plan.Tables[0].Table, Ordinal: 2, Rows: 1},
			{Table: plan.Tables[1].Table, Ordinal: 1, Rows: 3},
		},
		CommitOutcomeUnknown: true,
	}
	lines := applySummary(plan, report)
	text := strings.Join(lines, "\n")
	for _, want := range []string{
		"apply: complete=false committed_batches=3 committed_rows=6 outcome_unknown=true",
		"apply: table 1 batches=2 rows=3",
		"apply: table 2 batches=1 rows=3",
		"apply: last_committed table=2 batch=1 rows=3",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("summary missing %q: %q", want, text)
		}
	}
	for _, forbidden := range []string{"people", "contacts", "/", "key", "maskriver.local"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("summary contains forbidden %q: %q", forbidden, text)
		}
	}
	// A complete run has no interruption to locate, so it reports the accounted
	// work only.
	complete := applySummary(plan, contracts.ApplyReport{Committed: report.Committed, Complete: true})
	completeText := strings.Join(complete, "\n")
	if !strings.Contains(completeText, "apply: complete=true committed_batches=3 committed_rows=6") {
		t.Fatalf("complete summary=%q", completeText)
	}
	if strings.Contains(completeText, "last_committed") {
		t.Fatalf("complete summary claims an interrupted position: %q", completeText)
	}
}

// TestCLIScanFailureExitsNonZeroWithoutWrite covers the CLI half of the #9 scan
// failure gap. The command constructs its own readers, so a Reader wrapper with
// an injected fault can not cross the command boundary; the runner-level
// injection lives in internal/runner. What the command must still guarantee is
// that a Describe failure from the real SQLite adapter exits non-zero and changes
// neither snapshot.
func TestCLIScanFailureExitsNonZeroWithoutWrite(t *testing.T) {
	f := newE2EFixture(t, e2eOneTable...)
	// The target is a valid SQLite file without the declared table, so Scan fails
	// while reading the target schema rather than before any database work.
	if err := os.Remove(f.target); err != nil {
		t.Fatal(err)
	}
	cliExec(t, f.target, `CREATE TABLE unrelated (id INTEGER PRIMARY KEY)`)
	before := f.targetDigest(t)
	args := []string{"scan", "--source", f.source, "--target", f.target,
		"--scope", "people.email", "--min-samples", "1"}
	var out, errOut bytes.Buffer
	if code := run(args, &out, &errOut); code != 1 {
		t.Fatalf("scan exit=%d, want 1; output=%q", code, out.String()+errOut.String())
	}
	if f.targetDigest(t) != before {
		t.Fatal("failed scan changed the target")
	}
	output := out.String() + errOut.String()
	if !strings.Contains(output, "operation refused") {
		t.Fatalf("failed scan was not reported as a refusal: %q", output)
	}
	for _, secret := range f.secrets {
		if secret != "" && strings.Contains(output, secret) {
			t.Fatalf("failed scan leaked a fixture secret or path")
		}
	}
}

// TestCLINullStrategyRefusedBeforeWrite is the #9 regression for the null
// strategy. `mask --strategy null --apply` used to exit 0 and write NULL over
// every target value, and only the following strict validate rejected the
// result. The replacement can never pass validation, so the dry run must refuse
// it before a Writer opens and the target must stay byte-identical.
func TestCLINullStrategyRefusedBeforeWrite(t *testing.T) {
	f := newE2EFixture(t,
		`CREATE TABLE people (id INTEGER PRIMARY KEY, email TEXT NULL)`,
		`INSERT INTO people VALUES (1, 'e2e-alpha@example.invalid'), (2, 'e2e-beta@example.invalid'), (3, 'e2e-gamma@example.invalid')`,
	)
	plan := []string{"--source", f.source, "--target", f.target,
		"--strategy", "null", "--key-id", "synthetic-key", "--min-samples", "1",
		"--scope", "people.email"}
	approve := append(append([]string{"approve"}, plan...), f.review.reviewFlags()...)
	approve = append(approve, "--reviewer-id", "reviewer@synthetic.example")
	// The plan itself is buildable and the review decision is stored: the
	// refusal under test is the write gate, not the approval gate.
	f.run(t, 0, approve...)
	before := f.targetDigest(t)
	f.run(t, 1, append(append([]string{"mask"}, plan...), "--key-file", f.keyFile)...)
	if f.targetDigest(t) != before {
		t.Fatal("refused null-strategy preview changed the target")
	}
	apply := append(append([]string{"mask"}, plan...), "--key-file", f.keyFile)
	apply = append(apply, f.review.applyFlags()...)
	apply = append(apply, "--approved", "--apply")
	f.run(t, 1, apply...)
	if f.targetDigest(t) != before {
		t.Fatal("refused null-strategy apply changed the target")
	}
	// The target still holds every original value, so validation rejects an
	// unchanged target and not a written NULL replacement.
	f.run(t, 1, append(append([]string{"validate"}, plan...), "--key-file", f.keyFile, "--strict")...)
	if f.targetDigest(t) != before {
		t.Fatal("refused null-strategy run changed the target")
	}
}

// TestCLIStrictFlagWiring is the #9 regression for mutation M3: a --strict
// wiring that stops forwarding the flag or stops applying its verdict survived
// every earlier test. The two seams are replaced with recorders that also call
// the real implementation, so the command is observed end to end.
func TestCLIStrictFlagWiring(t *testing.T) {
	f := newE2EFixture(t, e2eOneTable...)
	scopes := []string{"people.email"}
	var requestStrict, passedStrict []bool
	request, passed := validationRequest, validationPassed
	t.Cleanup(func() { validationRequest, validationPassed = request, passed })
	validationRequest = func(plan contracts.Plan, strict bool) contracts.ValidateRequest {
		req := request(plan, strict)
		requestStrict = append(requestStrict, req.Strict)
		return req
	}
	validationPassed = func(report contracts.ValidationReport, strict bool) bool {
		passedStrict = append(passedStrict, strict)
		return passed(report, strict)
	}
	validate := func(wantCode int, strictArg string) {
		t.Helper()
		requestStrict, passedStrict = nil, nil
		args := append([]string{"validate"}, f.planArgs(scopes...)...)
		args = append(args, "--key-file", f.keyFile, strictArg)
		var out, errOut bytes.Buffer
		if code := run(args, &out, &errOut); code != wantCode {
			t.Fatalf("validate %s exit=%d want=%d; output=%q",
				strictArg, code, wantCode, out.String()+errOut.String())
		}
		if len(requestStrict) != 1 || len(passedStrict) != 1 {
			t.Fatalf("validate %s bypassed the strict wiring: request=%v passed=%v",
				strictArg, requestStrict, passedStrict)
		}
		want := strictArg == "--strict"
		if requestStrict[0] != want || passedStrict[0] != want {
			t.Fatalf("validate %s forwarded strict=%t/%t, want %t",
				strictArg, requestStrict[0], passedStrict[0], want)
		}
	}
	// The target is still unmasked, so the verdict is false under both settings;
	// a verdict hardcoded to pass would turn this exit into 0.
	validate(1, "--strict")
	validate(1, "--strict=false")
	f.run(t, 0, f.approveArgs(scopes...)...)
	f.run(t, 0, f.applyArgs(scopes...)...)
	// A completed apply validates cleanly under both settings; a verdict
	// hardcoded to fail would turn these exits into 1.
	validate(0, "--strict")
	validate(0, "--strict=false")
}

// TestValidationPassedHonorsStrictWarning pins the strict semantics the CLI
// depends on. verify currently never emits a complete report containing only a
// warning, which is exactly why this decision is tested directly instead of
// through a database fixture.
func TestValidationPassedHonorsStrictWarning(t *testing.T) {
	report := contracts.ValidationReport{
		PlanID:   "synthetic-plan",
		Coverage: contracts.Coverage{Complete: true, Tables: 1, Columns: 1, Rows: 1},
		Issues:   []contracts.Issue{{Status: contracts.Warning, Code: contracts.Unsupported, Count: 1}},
	}
	if validationPassed(report, true) {
		t.Fatal("strict validation accepted a warning-only report")
	}
	if !validationPassed(report, false) {
		t.Fatal("non-strict validation refused a warning-only complete report")
	}
}

func TestHelpCommandWritesStdout(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"help", "mask"}, &out, &errOut); code != 0 {
		t.Fatalf("exit=%d", code)
	}
	if !strings.Contains(out.String(), "Usage: maskriver mask [flags]") || errOut.Len() != 0 {
		t.Fatalf("help command did not write usage to stdout only: out=%q err=%q", out.String(), errOut.String())
	}
}
