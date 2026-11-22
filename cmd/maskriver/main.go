// Command maskriver runs the bounded, SQLite-only M1 workflow.
// Inputs must be pre-existing, separate disposable database snapshots.
//
// Write authorization is a two-part decision. `mask --apply` states intent, and
// Apply additionally requires an authenticated reviewer decision bound to exactly
// the plan. The decision is issued by the separate `approve` command with a
// reviewer private key and read back with the deployment trust file, so the apply
// invocation never receives a reviewer private key. `revoke` retires a decision.
//
// The recorded ReviewerID is a self-declared label. It is not an authenticated
// independent reviewer identity: the only authenticated fact is "the holder of
// the trusted key named by the decision signed this plan".
//
// Trust boundary, stated honestly: the trust file is a local deployment file, so
// an operator who controls both the trust file and the reviewer key file has not
// been prevented from approving their own plan. This is a local signature
// boundary, not a non-bypassable RBAC. Provisioning the trust file and the
// reviewer key under different authorities is a deployment responsibility this
// tool can not verify.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/haoyuehx/maskriver/internal/config"
	"github.com/haoyuehx/maskriver/internal/history"
	"github.com/haoyuehx/maskriver/internal/runner"
	"github.com/haoyuehx/maskriver/pkg/contracts"
)

const version = "1.0.1"

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

// run is the entry point main and the tests share. It owns the one-object stdout
// contract of `validate --format json`: whenever an invocation parsed and asked
// for JSON but never wrote a report — a configuration refusal, a plan failure or a
// validation error — the error object is emitted here instead of teaching every
// early return about output formats. An invocation whose format request was
// itself rejected keeps stdout empty, because it never agreed to speak JSON.
func run(args []string, stdout, stderr io.Writer) int {
	state := &outputState{}
	code := execute(args, stdout, stderr, state)
	if state.json && !state.emitted {
		emitValidateJSON(stdout, failedValidateJSONReport(state.strict))
	}
	return code
}

func execute(args []string, stdout, stderr io.Writer, state *outputState) int {
	if len(args) == 0 {
		usage(stdout)
		return 0
	}
	switch args[0] {
	case "help", "-h", "--help":
		if len(args) == 1 {
			usage(stdout)
			return 0
		}
		if args[0] == "help" && len(args) == 2 {
			if args[1] == "version" {
				fmt.Fprintln(stdout, "Usage: maskriver version")
				return 0
			}
			if knownCommand(args[1]) {
				// Command help is documentation, so send both streams to stdout.
				return run([]string{args[1], "--help"}, stdout, stdout)
			}
		}
		return usageError(stderr)
	case "version", "--version":
		if len(args) != 1 {
			return usageError(stderr)
		}
		fmt.Fprintln(stdout, "MaskRiver", version)
		return 0
	case "scan", "mask", "validate", "approve", "revoke", "init-outbox", "init-recovery", "status":
	default:
		return usageError(stderr)
	}
	if args[0] == "init-outbox" {
		return runInitOutbox(args[1:], stdout, stderr)
	}
	if args[0] == "init-recovery" {
		return runInitRecovery(args[1:], stdout, stderr)
	}
	if args[0] == "status" {
		return runStatus(args[1:], stdout, stderr)
	}
	command := args[0]
	// reviewCommand covers the explicit issuance surface. Neither command runs a
	// write on the database; they only build the plan and persist one decision.
	reviewCommand := command == "approve" || command == "revoke"
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	// The standard parser includes invalid values and unknown flag names in
	// its errors. Keep those details away from user-visible output.
	flags.SetOutput(io.Discard)
	cfg := config.Runtime{}
	var source, target, keyFile, dialectName string
	var trustFile, historyDir string
	var reviewerKeyID, reviewerKeyFile, reviewerID string
	var validFor time.Duration
	var apply, strict, streaming, resume bool
	var budgetFile, runID string
	var receiptPage int
	var operationTimeout time.Duration
	var strategy, keyID, format string
	var scopes scopeFlag
	flags.StringVar(&dialectName, "dialect", "sqlite", "database dialect: sqlite or mysql")
	flags.StringVar(&source, "source", "", "SQLite source path or MySQL source DSN")
	flags.StringVar(&target, "target", "", "SQLite target path or MySQL target DSN")
	flags.StringVar(&cfg.Table, "table", "", "explicit table allowlist (one table)")
	flags.StringVar(&cfg.Column, "column", "", "explicit sensitive column (one column)")
	flags.Var(&scopes, "scope", "explicit table.column scope; repeat for several scopes")
	flags.IntVar(&cfg.MinSamples, "min-samples", 20, "minimum distinct non-NULL evidence")
	flags.IntVar(&cfg.SampleLimit, "sample-limit", 128, "maximum distinct sampled inputs")
	flags.Float64Var(&cfg.MinRatio, "min-ratio", 0.9, "required rule hit ratio")
	flags.IntVar(&cfg.BatchSize, "batch-size", 64, "transaction batch size (1..1000)")
	flags.IntVar(&cfg.Workers, "workers", 1, "bounded masking workers (1..16)")
	if command != "scan" {
		flags.StringVar(&strategy, "strategy", "redact", "supported strategy identifier")
		flags.StringVar(&keyID, "key-id", "", "opaque ID for external Bytes key")
		if !reviewCommand {
			flags.StringVar(&keyFile, "key-file", "", "local key bytes file, never echoed")
		}
	}
	if command == "mask" || command == "validate" {
		flags.BoolVar(&cfg.Approved, "approved", false, "affirm a separately reviewed column decision")
	}
	if command == "mask" {
		flags.BoolVar(&apply, "apply", false, "explicitly request writes after full preview")
		flags.BoolVar(&streaming, "streaming", false, "use the explicit m2-stream-v1 transaction/outbox path")
		flags.BoolVar(&resume, "resume", false, "resume an existing m2-recovery-v1 run (requires --streaming --apply --run-id)")
		flags.StringVar(&trustFile, "trust-file", "", "deployment-provisioned reviewer trust file (required with --apply)")
		flags.StringVar(&historyDir, "history-dir", "", "review-decision store directory (required with --apply)")
		flags.StringVar(&budgetFile, "budget-file", "", "explicit ResourceBudget JSON (required with --streaming)")
		flags.StringVar(&runID, "run-id", "", "32-hex run identity (generated when omitted)")
		flags.IntVar(&receiptPage, "receipt-page-size", 0, "receipt page bound (required with --streaming)")
		flags.DurationVar(&operationTimeout, "timeout", 2*time.Minute, "operation deadline (1s..24h)")
	}
	if command == "validate" {
		flags.BoolVar(&strict, "strict", true, "refuse any incomplete or warning coverage")
		flags.StringVar(&format, "format", "text", "output format: text (default) or json")
	}
	if reviewCommand {
		flags.BoolVar(&streaming, "streaming", false, "issue/read an m2 streaming approval instead of a legacy m1 decision")
		flags.StringVar(&trustFile, "trust-file", "", "deployment-provisioned reviewer trust file")
		flags.StringVar(&historyDir, "history-dir", "", "review-decision store directory")
		flags.StringVar(&reviewerKeyID, "reviewer-key-id", "", "trusted signer key id the reviewer key belongs to")
		flags.StringVar(&reviewerKeyFile, "reviewer-key-file", "", "local reviewer Ed25519 private key file, never echoed")
	}
	if command == "approve" {
		flags.StringVar(&reviewerID, "reviewer-id", "", "self-declared reviewer label recorded in the decision")
		flags.DurationVar(&validFor, "valid-for", 24*time.Hour, "decision validity window")
	}
	// Usage always follows the FlagSet output stream so that help is printed
	// exactly once: discarded during Parse, then re-enabled only for -h.
	flags.Usage = func() {
		out := flags.Output()
		fmt.Fprintf(out, "Usage: maskriver %s [flags]\n", command)
		flags.PrintDefaults()
	}
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			flags.SetOutput(stderr)
			flags.Usage()
			return 0
		}
		return usageError(stderr)
	}
	if flags.NArg() != 0 {
		return usageError(stderr)
	}
	// --format is the only flag that changes the stdout contract, so an unknown
	// value is refused as a usage error before any work starts. The value is not
	// echoed: argument errors stay sanitized.
	if command == "validate" {
		switch format {
		case "text":
		case "json":
			state.json = true
			state.strict = strict
		default:
			return usageError(stderr)
		}
	}
	// -scope and -table/-column are two spellings of the same declaration;
	// mixing them would be ambiguous, so it is refused rather than merged.
	if len(scopes) > 0 {
		if cfg.Table != "" || cfg.Column != "" {
			return usageError(stderr)
		}
		cfg.Scopes = scopes
	}
	switch strings.ToLower(strings.TrimSpace(dialectName)) {
	case "sqlite":
		cfg.Dialect = contracts.SQLite
	case "mysql":
		cfg.Dialect = contracts.MySQL
	default:
		return fail(stderr, 2)
	}
	var err error
	if cfg.Dialect == contracts.SQLite {
		cfg.Source, err = filepath.Abs(source)
		if err != nil || source == "" {
			return fail(stderr, 2)
		}
		cfg.Target, err = filepath.Abs(target)
		if err != nil || target == "" {
			return fail(stderr, 2)
		}
	} else {
		// MySQL DSNs are opaque and may contain credentials; never rewrite them
		// with filepath.Abs and never print them.
		cfg.Source, cfg.Target = source, target
	}
	if err := cfg.Validate(); err != nil {
		return fail(stderr, 2)
	}
	if cfg.Dialect == contracts.MySQL && (streaming || resume) {
		return fail(stderr, 2) // MySQL streaming/recovery has no approved protocol
	}
	cfg.Strategy = contracts.StrategyRef{ID: strategy, Version: "1"}
	cfg.KeyID = keyID
	if command == "mask" && apply && !cfg.Approved {
		return fail(stderr, 2) // rule classification alone never grants writes
	}
	if command == "mask" && streaming && !apply {
		return fail(stderr, 2) // --streaming never replaces explicit write intent
	}
	if command == "mask" && resume {
		// Resume is a separate explicit entry point: it must name an existing
		// run and can never generate or rename one.
		if !streaming || !apply || runID == "" || !contracts.ValidRunID(runID) {
			return fail(stderr, 2)
		}
	}
	if command == "mask" && !resume && runID != "" && !contracts.ValidRunID(runID) {
		return fail(stderr, 2)
	}
	// The review commands state every deployment input explicitly. A missing
	// trust file or reviewer key is a configuration error, not an operation
	// refusal, so it exits 2 without echoing a path.
	if reviewCommand {
		if trustFile == "" || historyDir == "" || reviewerKeyID == "" || reviewerKeyFile == "" || keyID == "" {
			return fail(stderr, 2)
		}
		if command == "approve" && (reviewerID == "" || validFor <= 0) {
			return fail(stderr, 2)
		}
	}
	var key contracts.Value
	if command == "mask" || command == "validate" {
		if keyFile == "" || keyID == "" {
			return fail(stderr, 2)
		}
		info, err := os.Stat(keyFile)
		if err != nil || !info.Mode().IsRegular() || info.Size() < 32 || info.Size() > 4096 {
			return fail(stderr, 2)
		}
		content, err := os.ReadFile(keyFile)
		if err != nil {
			return fail(stderr, 2)
		}
		key, err = contracts.NewValue(contracts.Bytes, string(content))
		if err != nil {
			return fail(stderr, 2)
		}
	}
	if command == "mask" && apply && (trustFile == "" || historyDir == "") {
		return fail(stderr, 2)
	}
	var budget contracts.ResourceBudget
	if command == "mask" && streaming {
		if budgetFile == "" || receiptPage <= 0 {
			return fail(stderr, 2)
		}
		budget, err = loadResourceBudget(budgetFile)
		if err != nil || receiptPage > budget.MaxReceiptPage || cfg.BatchSize > budget.MaxBatchSize ||
			cfg.Workers > budget.MaxWorkers {
			return fail(stderr, 2)
		}
	}
	var reviewStore *history.Store
	if reviewCommand {
		reviewStore, err = openSigningStore(trustFile, historyDir, reviewerKeyID, reviewerKeyFile)
		if err != nil {
			return fail(stderr, 2)
		}
	}
	if command == "mask" && (operationTimeout < time.Second || operationTimeout > 24*time.Hour) {
		return fail(stderr, 2)
	}
	if command != "mask" {
		operationTimeout = 2 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), operationTimeout)
	defer cancel()
	var engine *runner.Engine
	if command == "mask" && apply {
		engine, err = runner.OpenForApply(ctx, cfg, key)
	} else {
		engine, err = runner.Open(ctx, cfg, key)
	}
	if err != nil {
		return fail(stderr, 1)
	}
	defer engine.Close()
	if command == "scan" {
		report, err := engine.Scan(ctx, contracts.ScanRequest{})
		if err != nil {
			return fail(stderr, 1)
		}
		fmt.Fprintf(stdout, "scan: complete=%t columns=%d issues=%d\n",
			report.Coverage.Complete, report.Coverage.Columns, len(report.Issues))
		if !report.Coverage.Complete {
			return 1
		}
		return 0
	}
	plan, err := engine.Plan(ctx)
	if err != nil {
		return fail(stderr, 1)
	}
	if reviewCommand {
		return issueDecision(ctx, command, reviewStore, plan, reviewerID, validFor, streaming, stdout, stderr)
	}
	if command == "validate" {
		report, err := engine.Validate(ctx, validationRequest(plan, strict))
		if err != nil {
			return fail(stderr, 1)
		}
		passed := validationPassed(report, strict)
		summary := fmt.Sprintf("validate: pass=%t tables=%d rows=%d issues=%d\n",
			passed, report.Coverage.Tables, report.Coverage.Rows, len(report.Issues))
		if state.json {
			// The human summary is still produced, but it is a diagnostic in JSON
			// mode: stderr keeps it and stdout carries the single report object.
			fmt.Fprint(stderr, summary)
			emitValidateJSON(stdout, validateJSONFromReport(report, strict, passed))
			state.emitted = true
		} else {
			fmt.Fprint(stdout, summary)
		}
		if !passed {
			return 1
		}
		return 0
	}
	if !apply {
		report, err := engine.Preview(ctx, contracts.PreviewRequest{Plan: plan})
		if err != nil {
			return fail(stderr, 1)
		}
		fmt.Fprintf(stdout, "preview: dry-run=true rows=%d complete=%t (no row values shown)\n",
			report.RowsRead, report.Coverage.Complete)
		return 0
	}
	// Apply reads the decision through a read-only query. The trust set comes from
	// the deployment trust file and no reviewer private key exists on this path.
	trust, err := history.LoadTrustFile(trustFile)
	if err != nil {
		return fail(stderr, 2)
	}
	storeCfg := history.Config{Dir: historyDir, Trust: trust}
	if streaming {
		// The streaming run's declared history bounds apply to every directory
		// enumeration this process performs.
		storeCfg.MaxEntries = budget.MaxHistoryEntries
		storeCfg.MaxNameBytes = int(budget.MaxHistoryNameBytes)
	}
	approvalStore, err := history.Open(storeCfg)
	if err != nil {
		return fail(stderr, 2)
	}
	if streaming {
		return streamingApplyOrResume(ctx, engine, approvalStore, plan, cfg, budget, runID, receiptPage, resume, stdout, stderr)
	}
	engine.SetApprovalQuery(approvalStore)
	report, err := engine.Apply(ctx, contracts.ApplyRequest{
		Plan: plan, ExplicitApply: true, BatchSize: cfg.BatchSize,
	})
	// The summary names tables by their 1-based position in the plan and reports
	// only counts: the report carries no value, primary key, path, DSN or key
	// material, so none can be printed.
	if err != nil {
		for _, line := range applySummary(plan, report) {
			fmt.Fprintln(stderr, line)
		}
		return 1
	}
	for _, line := range applySummary(plan, report) {
		fmt.Fprintln(stdout, line)
	}
	if !report.Complete {
		return 1
	}
	return 0
}

// validationRequest and validationPassed are the validate command's only two
// uses of the --strict flag: one sends it to the validator, the other applies it
// to the verdict. They are variables so the CLI wiring test can observe the flag
// at runtime: the frozen verifier ignores req.Strict and never emits a complete
// report containing only Warning issues, so no database fixture can distinguish
// strict from non-strict through exit codes alone.
var (
	validationRequest = func(plan contracts.Plan, strict bool) contracts.ValidateRequest {
		return contracts.ValidateRequest{Plan: plan, Strict: strict}
	}
	validationPassed = func(report contracts.ValidationReport, strict bool) bool {
		return report.Passed(strict)
	}
)

// openSigningStore builds the write-capable review store from deployment files.
// The trust set and the reviewer key only meet here: the trust entry names the
// public key, and history.Open refuses a private key that is not that key.
func openSigningStore(trustFile, historyDir, reviewerKeyID, reviewerKeyFile string) (*history.Store, error) {
	trust, err := history.LoadTrustFile(trustFile)
	if err != nil {
		return nil, err
	}
	private, err := history.LoadSignerKeyFile(reviewerKeyFile)
	if err != nil {
		return nil, err
	}
	return history.Open(history.Config{
		Dir: historyDir, Trust: trust,
		Signer: &history.Signer{SignerKeyID: reviewerKeyID, Private: private},
	})
}

// issueDecision persists one explicit reviewer decision. The printed summary
// carries counts and the requested window only: no plan id, path, key or value.
func issueDecision(ctx context.Context, command string, store *history.Store, plan contracts.Plan,
	reviewerID string, validFor time.Duration, streaming bool, stdout, stderr io.Writer) int {
	if streaming {
		if command == "revoke" {
			if _, err := store.RevokeStreaming(ctx, plan, time.Now()); err != nil {
				return fail(stderr, 1)
			}
			fmt.Fprintln(stdout, "revoke: stored=true protocol=m2-stream-v1")
			return 0
		}
		now := time.Now()
		record, err := store.ApproveStreaming(ctx, history.StreamingApproveRequest{
			Plan: plan, ReviewerID: reviewerID,
			IssuedAt: now, ExpiresAt: now.Add(validFor),
		})
		if err != nil {
			return fail(stderr, 1)
		}
		fmt.Fprintf(stdout, "approve: stored=true protocol=m2-stream-v1 scopes=%d valid_for=%s\n",
			len(record.Scopes), validFor)
		return 0
	}
	if command == "revoke" {
		if _, err := store.Revoke(ctx, history.RevokeRequest{Plan: plan, RevokedAt: time.Now()}); err != nil {
			return fail(stderr, 1)
		}
		fmt.Fprintln(stdout, "revoke: stored=true")
		return 0
	}
	now := time.Now()
	record, err := store.Approve(ctx, history.ApproveRequest{
		Plan: plan, ReviewerID: reviewerID,
		IssuedAt: now, ExpiresAt: now.Add(validFor),
	})
	if err != nil {
		return fail(stderr, 1)
	}
	fmt.Fprintf(stdout, "approve: stored=true scopes=%d valid_for=%s\n", len(record.Scopes), validFor)
	return 0
}

// applySummary renders the sanitized accounting of one Apply call: the plan
// position of every table (1-based, in plan order), the batches committed for it
// and the rows those batches wrote, the last committed batch position, and the
// completeness/unknown-outcome flags of the run. Table positions are printed
// instead of table names so the summary stays free of database identifiers.
func applySummary(plan contracts.Plan, report contracts.ApplyReport) []string {
	positions := make(map[contracts.TableRef]int, len(plan.Tables))
	batches := make([]int64, len(plan.Tables))
	rows := make([]int64, len(plan.Tables))
	var committedRows int64
	for i, table := range plan.Tables {
		positions[table.Table] = i + 1
	}
	for _, receipt := range report.Committed {
		committedRows += receipt.Rows
		position, ok := positions[receipt.Table]
		if !ok {
			continue
		}
		batches[position-1]++
		rows[position-1] += receipt.Rows
	}
	lines := []string{fmt.Sprintf(
		"apply: complete=%t committed_batches=%d committed_rows=%d outcome_unknown=%t",
		report.Complete, len(report.Committed), committedRows, report.CommitOutcomeUnknown)}
	for i := range plan.Tables {
		lines = append(lines, fmt.Sprintf("apply: table %d batches=%d rows=%d",
			i+1, batches[i], rows[i]))
	}
	// The last committed batch position is what locates an interruption: a
	// complete run has nothing to locate.
	if n := len(report.Committed); n > 0 && !report.Complete {
		last := report.Committed[n-1]
		lines = append(lines, fmt.Sprintf("apply: last_committed table=%d batch=%d rows=%d",
			positions[last.Table], last.Ordinal, last.Rows))
	}
	return lines
}

// scopeFlag collects repeated -scope table.column values in declaration order.
// Declared order is preserved because it is the deterministic plan order.
type scopeFlag []config.Scope

// errScopeFormat carries no user input: the flag package embeds Set errors into
// its own discarded output, and the CLI prints one sanitized message instead.
var errScopeFormat = errors.New("scope must be table.column")

func (f *scopeFlag) String() string {
	if f == nil {
		return ""
	}
	parts := make([]string, 0, len(*f))
	for _, scope := range *f {
		parts = append(parts, scope.Table+"."+scope.Column)
	}
	return strings.Join(parts, ",")
}

func (f *scopeFlag) Set(raw string) error {
	table, column, ok := strings.Cut(raw, ".")
	if !ok || table == "" || column == "" || strings.Contains(column, ".") {
		return errScopeFormat
	}
	*f = append(*f, config.Scope{Table: table, Column: column})
	return nil
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "MaskRiver — SQLite/MySQL masking preview; SQLite streaming and local recovery")
	fmt.Fprintln(w, "Usage: maskriver <scan|mask|validate|approve|revoke|init-outbox|init-recovery|status|version> [flags]")
	fmt.Fprintln(w, "Two independent pre-existing SQLite files, or two MySQL DSNs (--dialect mysql), are required; mask defaults to dry run.")
	fmt.Fprintln(w, "MySQL streaming/recovery is not supported; m2-stream-v1/m2-recovery-v1 remain SQLite-only.")
	fmt.Fprintln(w, "mask --apply --approved also requires a stored reviewer decision bound to the plan.")
	fmt.Fprintln(w, "mask --streaming --apply --resume --run-id <32-hex> resumes m2-recovery-v1.")
	fmt.Fprintln(w, "status --target <db> --run-id <32-hex> is read-only; it never recovers or writes.")
	fmt.Fprintln(w, "validate --format json writes one JSON object to stdout; diagnostics stay on stderr.")
	fmt.Fprintln(w, "approve/revoke sign with a reviewer key; apply reads the deployment trust file only.")
	fmt.Fprintln(w, "A local operator controlling both trust file and reviewer key is not stopped by RBAC.")
	fmt.Fprintln(w, "Examples:")
	fmt.Fprintln(w, "  maskriver help mask")
	fmt.Fprintln(w, "  maskriver scan --source /work/source.db --target /work/target.db --scope people.email")
	fmt.Fprintln(w, "  maskriver scan --dialect mysql --source '<dsn>' --target '<dsn>' --scope people.born")
	fmt.Fprintln(w, "  maskriver mask ... --trust-file trust.json --history-dir history --approved --apply")
	fmt.Fprintln(w, "  maskriver validate --strict ...")
	fmt.Fprintln(w, "Use authorized synthetic copies.")
}

func knownCommand(command string) bool {
	switch command {
	case "scan", "mask", "validate", "approve", "revoke", "init-outbox", "init-recovery", "status", "version":
		return true
	}
	return false
}

func usageError(w io.Writer) int {
	fmt.Fprintln(w, "invalid arguments; use maskriver --help")
	return 2
}

func fail(w io.Writer, code int) int {
	fmt.Fprintln(w, "operation refused or incomplete (sanitized; no database values or DSN)")
	return code
}
