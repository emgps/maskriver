package main

// Tests for issue #115: `validate --format json`. The report is the contract an
// automated acceptance run reads, so its exact shape is pinned field by field, and
// stream separation, exit-code agreement and the disclosure boundary are each
// proven rather than assumed.

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/haoyuehx/maskriver/pkg/contracts"
)

// e2eForbiddenInJSON are the shapes a machine-readable report must never contain:
// stored cell values, database file names, schema identifiers, deployment paths
// and reviewer material. They are checked literally because a JSON report has no
// human to notice a leak.
var e2eForbiddenInJSON = []string{
	"example.invalid", "source.db", "target.db", "masking.key",
	"trust.json", "people", "email", "reviewer", "PRIVATE KEY",
}

// decodeSingleJSONObject decodes exactly one JSON object from raw and fails if any
// second value follows. It returns the raw field map so a test can pin the key set.
func decodeSingleJSONObject(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var object map[string]any
	if err := decoder.Decode(&object); err != nil {
		t.Fatalf("stdout is not a JSON object: %v; raw=%q", err, raw)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		t.Fatalf("stdout carried more than one JSON value: raw=%q", raw)
	}
	return object
}

// requireKeys asserts the exact key set of one decoded object. An extra key would
// silently widen the report's disclosure surface.
func requireKeys(t *testing.T, where string, object map[string]any, want ...string) {
	t.Helper()
	got := make([]string, 0, len(object))
	for key := range object {
		got = append(got, key)
	}
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("%s has keys %v, want exactly %v", where, got, want)
	}
}

// assertNoSecrets applies the fixture's own disclosure check and the JSON-specific
// forbidden shapes to one stream.
func assertNoSecrets(t *testing.T, f *e2eFixture, stream, text string) {
	t.Helper()
	for _, secret := range f.secrets {
		if secret != "" && strings.Contains(text, secret) {
			t.Fatalf("%s leaked a fixture secret: %q", stream, text)
		}
	}
	for _, forbidden := range e2eForbiddenInJSON {
		if strings.Contains(text, forbidden) {
			t.Fatalf("%s leaked %q: %q", stream, forbidden, text)
		}
	}
}

// runValidateJSON runs one in-process validate invocation with separate streams.
// Separate buffers are the point: the child-process fixture runner merges stdout
// and stderr, and stream separation is what this file has to prove.
func runValidateJSON(t *testing.T, f *e2eFixture, scopes ...string) (int, []byte, string) {
	t.Helper()
	args := append([]string{"validate"}, f.planArgs(scopes...)...)
	args = append(args, "--key-file", f.keyFile, "--strict", "--format", "json")
	var out, errOut bytes.Buffer
	code := run(args, &out, &errOut)
	if out.Len() > 0 && !bytes.HasSuffix(out.Bytes(), []byte("\n")) {
		t.Fatalf("JSON report has no trailing newline: %q", out.String())
	}
	return code, out.Bytes(), errOut.String()
}

// runValidateText runs the same invocation in the default text mode so the two
// output modes can be compared for identical verdicts.
func runValidateText(t *testing.T, f *e2eFixture, scopes ...string) (int, string, string) {
	t.Helper()
	args := append([]string{"validate"}, f.planArgs(scopes...)...)
	args = append(args, "--key-file", f.keyFile, "--strict")
	var out, errOut bytes.Buffer
	code := run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

// TestValidateJSONReportShape pins the schema of one report: the exact key set at
// every level, the status vocabulary, the issue projection, and the absence of
// table, column or plan identifiers even when the source issue carries them.
func TestValidateJSONReportShape(t *testing.T) {
	column := contracts.ColumnRef{
		TableRef: contracts.TableRef{Database: "maskriver", Schema: "main", Table: "people"},
		Column:   "email",
	}
	report := contracts.ValidationReport{
		PlanID:   "synthetic-plan",
		Coverage: contracts.Coverage{Complete: true, Tables: 1, Columns: 2, Rows: 3},
		Issues: []contracts.Issue{
			{Status: contracts.Fail, Code: contracts.UnchangedValue, Column: column, Count: 2},
			{Status: contracts.Warning, Code: contracts.Unsupported, Count: 1},
		},
	}

	var raw bytes.Buffer
	emitValidateJSON(&raw, validateJSONFromReport(report, true, false))
	object := decodeSingleJSONObject(t, raw.Bytes())
	requireKeys(t, "report", object,
		"schema_version", "status", "complete", "strict", "coverage", "issues")

	if object["schema_version"] != validateJSONSchemaVersion {
		t.Fatalf("schema_version=%v, want %q", object["schema_version"], validateJSONSchemaVersion)
	}
	// The verdict is supplied by the same seam the exit code uses, so a failing
	// report can never claim to pass.
	if object["status"] != validateStatusFail {
		t.Fatalf("status=%v, want %q", object["status"], validateStatusFail)
	}
	if object["complete"] != true || object["strict"] != true {
		t.Fatalf("complete/strict=%v/%v, want true/true", object["complete"], object["strict"])
	}
	coverage, ok := object["coverage"].(map[string]any)
	if !ok {
		t.Fatalf("coverage is not an object: %v", object["coverage"])
	}
	requireKeys(t, "coverage", coverage, "tables", "columns", "rows")
	if coverage["tables"] != float64(1) || coverage["columns"] != float64(2) || coverage["rows"] != float64(3) {
		t.Fatalf("coverage=%v, want 1/2/3", coverage)
	}
	issues, ok := object["issues"].([]any)
	if !ok {
		t.Fatalf("issues is not an array: %v", object["issues"])
	}
	if len(issues) != 2 {
		t.Fatalf("issues=%d, want 2", len(issues))
	}
	first, ok := issues[0].(map[string]any)
	if !ok {
		t.Fatalf("issue is not an object: %v", issues[0])
	}
	requireKeys(t, "issue", first, "status", "code", "count")
	if first["status"] != "fail" || first["code"] != string(contracts.UnchangedValue) || first["count"] != float64(2) {
		t.Fatalf("issue=%v, want fail/unchanged_value/2", first)
	}
	second := issues[1].(map[string]any)
	if second["status"] != "warning" || second["code"] != "unsupported" {
		t.Fatalf("issue=%v, want warning/unsupported", second)
	}
	// The source issue names a table, a schema and a column; the report must not,
	// and neither may it expose the plan digest.
	for _, forbidden := range []string{"people", "email", `"main"`, "synthetic-plan"} {
		if strings.Contains(raw.String(), forbidden) {
			t.Fatalf("report leaked %q: %q", forbidden, raw.String())
		}
	}

	// Non-strict mode is recorded as the setting it was, and a passing report
	// carries an always-present empty issue array rather than null.
	var passing bytes.Buffer
	emitValidateJSON(&passing, validateJSONFromReport(
		contracts.ValidationReport{Coverage: contracts.Coverage{Complete: true, Tables: 1, Columns: 1, Rows: 1}},
		false, true,
	))
	clean := decodeSingleJSONObject(t, passing.Bytes())
	if clean["status"] != validateStatusPass || clean["strict"] != false {
		t.Fatalf("clean report status/strict=%v/%v, want pass/false", clean["status"], clean["strict"])
	}
	if empty, ok := clean["issues"].([]any); !ok || len(empty) != 0 {
		t.Fatalf("clean report issues=%v, want an empty array", clean["issues"])
	}
}

// TestCLIValidateJSONVerdictMatchesTextAndExitCode walks the same fixture through
// both output modes before and after masking. Both modes must agree on the verdict
// and the exit code, while JSON mode moves the human summary to stderr and keeps
// stdout a single object.
func TestCLIValidateJSONVerdictMatchesTextAndExitCode(t *testing.T) {
	f := newE2EFixture(t, e2eOneTable...)
	scopes := []string{"people.email"}

	// The target is still unmasked, so strict validation must fail.
	jsonCode, raw, jsonErr := runValidateJSON(t, f, scopes...)
	textCode, textOut, textErr := runValidateText(t, f, scopes...)
	if jsonCode != 1 || textCode != 1 {
		t.Fatalf("unmasked target: json exit=%d text exit=%d, want 1/1", jsonCode, textCode)
	}
	object := decodeSingleJSONObject(t, raw)
	requireKeys(t, "report", object,
		"schema_version", "status", "complete", "strict", "coverage", "issues")
	if object["status"] != validateStatusFail {
		t.Fatalf("unmasked target status=%v, want %q", object["status"], validateStatusFail)
	}
	if object["complete"] != true {
		t.Fatalf("unmasked target complete=%v, want true", object["complete"])
	}
	// The summary is a diagnostic in JSON mode and belongs to stderr.
	if !strings.Contains(jsonErr, "validate: pass=false") {
		t.Fatalf("JSON mode did not route the summary to stderr: %q", jsonErr)
	}
	if strings.Contains(string(raw), "validate:") {
		t.Fatalf("JSON mode left the summary on stdout: %q", raw)
	}
	// Text mode is unchanged: summary on stdout, nothing on stderr.
	if !strings.Contains(textOut, "validate: pass=false") {
		t.Fatalf("text mode summary missing from stdout: %q", textOut)
	}
	if textErr != "" {
		t.Fatalf("text mode wrote to stderr: %q", textErr)
	}
	// The failing evidence is carried as codes, not as values or identifiers.
	issues := object["issues"].([]any)
	if len(issues) == 0 {
		t.Fatal("failing report carried no issue evidence")
	}
	codes := make(map[string]bool, len(issues))
	for _, item := range issues {
		issue := item.(map[string]any)
		requireKeys(t, "issue", issue, "status", "code", "count")
		codes[issue["code"].(string)] = true
	}
	if !codes[string(contracts.UnchangedValue)] {
		t.Fatalf("failing report codes=%v, want unchanged_value", codes)
	}
	assertNoSecrets(t, f, "json stdout", string(raw))
	assertNoSecrets(t, f, "json stderr", jsonErr)

	// A completed apply makes the same target pass in both modes.
	f.run(t, 0, f.approveArgs(scopes...)...)
	f.run(t, 0, f.applyArgs(scopes...)...)
	jsonCode, raw, jsonErr = runValidateJSON(t, f, scopes...)
	textCode, textOut, textErr = runValidateText(t, f, scopes...)
	if jsonCode != 0 || textCode != 0 {
		t.Fatalf("masked target: json exit=%d text exit=%d, want 0/0", jsonCode, textCode)
	}
	object = decodeSingleJSONObject(t, raw)
	if object["status"] != validateStatusPass {
		t.Fatalf("masked target status=%v, want %q", object["status"], validateStatusPass)
	}
	if issues, ok := object["issues"].([]any); !ok || len(issues) != 0 {
		t.Fatalf("masked target issues=%v, want an empty array", object["issues"])
	}
	if !strings.Contains(jsonErr, "validate: pass=true") {
		t.Fatalf("JSON mode did not route the summary to stderr: %q", jsonErr)
	}
	if !strings.Contains(textOut, "validate: pass=true") || textErr != "" {
		t.Fatalf("text mode changed: out=%q err=%q", textOut, textErr)
	}
	assertNoSecrets(t, f, "json stdout", string(raw))
	assertNoSecrets(t, f, "json stderr", jsonErr)
}

// TestCLIValidateJSONRuntimeErrorEmitsOneObject covers the failure that happens
// while the command runs. It must still produce exactly one object, with empty
// evidence and no claimed completeness, while the sanitized reason stays on stderr.
func TestCLIValidateJSONRuntimeErrorEmitsOneObject(t *testing.T) {
	f := newE2EFixture(t, e2eOneTable...)
	// Replace the target with a valid SQLite file that lacks the declared table, so
	// the command fails after parsing, while it is doing database work.
	if err := os.Remove(f.target); err != nil {
		t.Fatal(err)
	}
	cliExec(t, f.target, `CREATE TABLE unrelated (id INTEGER PRIMARY KEY)`)

	var out, errOut bytes.Buffer
	args := append([]string{"validate"}, f.planArgs("people.email")...)
	args = append(args, "--key-file", f.keyFile, "--format", "json")
	if code := run(args, &out, &errOut); code != 1 {
		t.Fatalf("runtime error exit=%d, want 1; out=%q err=%q", code, out.String(), errOut.String())
	}
	object := decodeSingleJSONObject(t, out.Bytes())
	requireKeys(t, "error report", object,
		"schema_version", "status", "complete", "strict", "coverage", "issues")
	if object["status"] != validateStatusError {
		t.Fatalf("error report status=%v, want %q", object["status"], validateStatusError)
	}
	// No verdict was reached, so no coverage may be claimed.
	if object["complete"] != false {
		t.Fatalf("error report complete=%v, want false", object["complete"])
	}
	coverage := object["coverage"].(map[string]any)
	requireKeys(t, "coverage", coverage, "tables", "columns", "rows")
	for _, key := range []string{"tables", "columns", "rows"} {
		if coverage[key] != float64(0) {
			t.Fatalf("error report coverage[%s]=%v, want 0", key, coverage[key])
		}
	}
	if issues, ok := object["issues"].([]any); !ok || len(issues) != 0 {
		t.Fatalf("error report issues=%v, want an empty array", object["issues"])
	}
	// The reason is the existing sanitized diagnostic, and it stays on stderr.
	if !strings.Contains(errOut.String(), "operation refused") {
		t.Fatalf("missing sanitized diagnostic: %q", errOut.String())
	}
	if strings.Contains(out.String(), "operation refused") {
		t.Fatalf("diagnostic leaked into stdout: %q", out.String())
	}
	assertNoSecrets(t, f, "json stdout", out.String())
	assertNoSecrets(t, f, "json stderr", errOut.String())
}

// TestCLIValidateJSONUsageRefusals pins both refusal shapes: a rejected format
// never promises JSON and is not echoed, while a configuration refusal after an
// accepted format still emits one object so a consumer never parses empty stdout.
func TestCLIValidateJSONUsageRefusals(t *testing.T) {
	// An unknown format is a usage error before any JSON promise exists.
	var out, errOut bytes.Buffer
	if code := run([]string{"validate", "--format", "yaml"}, &out, &errOut); code != 2 {
		t.Fatalf("unknown format exit=%d, want 2", code)
	}
	if out.Len() != 0 {
		t.Fatalf("rejected format wrote to stdout: %q", out.String())
	}
	if !strings.Contains(errOut.String(), "invalid arguments") {
		t.Fatalf("missing sanitized usage error: %q", errOut.String())
	}
	// The rejected value must not be echoed back.
	if strings.Contains(errOut.String(), "yaml") {
		t.Fatalf("usage error echoed the format value: %q", errOut.String())
	}

	// --format belongs to validate; another command must refuse it.
	out.Reset()
	errOut.Reset()
	if code := run([]string{"scan", "--format", "json"}, &out, &errOut); code != 2 {
		t.Fatalf("scan --format exit=%d, want 2", code)
	}
	if out.Len() != 0 {
		t.Fatalf("scan --format wrote to stdout: %q", out.String())
	}

	// A configuration refusal after --format json was accepted: the report still
	// arrives, marked as an error, with the diagnostic on stderr.
	f := newE2EFixture(t, e2eOneTable...)
	args := append([]string{"validate"}, f.planArgs("people.email")...)
	args = append(args, "--format", "json") // no --key-file on purpose
	out.Reset()
	errOut.Reset()
	if code := run(args, &out, &errOut); code != 2 {
		t.Fatalf("config refusal exit=%d, want 2; err=%q", code, errOut.String())
	}
	object := decodeSingleJSONObject(t, out.Bytes())
	requireKeys(t, "refusal report", object,
		"schema_version", "status", "complete", "strict", "coverage", "issues")
	if object["status"] != validateStatusError {
		t.Fatalf("refusal report status=%v, want %q", object["status"], validateStatusError)
	}
	if !strings.Contains(errOut.String(), "operation refused") {
		t.Fatalf("missing sanitized refusal: %q", errOut.String())
	}
	assertNoSecrets(t, f, "json stdout", out.String())
	assertNoSecrets(t, f, "json stderr", errOut.String())
}
