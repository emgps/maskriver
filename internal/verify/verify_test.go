package verify

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/haoyuehx/maskriver/pkg/contracts"
)

// ---------------------------------------------------------------------------
// Fake Reader (in-memory, no DB dependency; required by issue #8 scope)
// ---------------------------------------------------------------------------

type fakeTable struct {
	schema contracts.TableSchema
	rows   []contracts.Row
}

type fakeReader struct {
	tables map[contracts.TableRef]fakeTable
	// injectable errors
	describeErr map[contracts.TableRef]error
	countErr    map[contracts.TableRef]error
	pageErr     map[contracts.TableRef]error
}

func newFakeReader() *fakeReader {
	return &fakeReader{
		tables:      make(map[contracts.TableRef]fakeTable),
		describeErr: make(map[contracts.TableRef]error),
		countErr:    make(map[contracts.TableRef]error),
		pageErr:     make(map[contracts.TableRef]error),
	}
}

func (f *fakeReader) addTable(t contracts.TableRef, schema contracts.TableSchema, rows []contracts.Row) {
	schema.Ref = t
	f.tables[t] = fakeTable{schema: schema, rows: rows}
}

func (f *fakeReader) Tables(_ context.Context, _ []string) ([]contracts.TableRef, error) {
	out := make([]contracts.TableRef, 0, len(f.tables))
	for t := range f.tables {
		out = append(out, t)
	}
	return out, nil
}

func (f *fakeReader) Describe(_ context.Context, t contracts.TableRef) (contracts.TableSchema, error) {
	if err, ok := f.describeErr[t]; ok {
		return contracts.TableSchema{}, err
	}
	tbl, ok := f.tables[t]
	if !ok {
		return contracts.TableSchema{}, contracts.ErrNotFound
	}
	return tbl.schema, nil
}

func (f *fakeReader) Sample(_ context.Context, _ contracts.SampleRequest) (contracts.Sample, error) {
	return contracts.Sample{}, nil
}

func (f *fakeReader) Count(_ context.Context, t contracts.TableRef) (int64, error) {
	if err, ok := f.countErr[t]; ok {
		return 0, err
	}
	tbl, ok := f.tables[t]
	if !ok {
		return 0, contracts.ErrNotFound
	}
	return int64(len(tbl.rows)), nil
}

// Page implements keyset pagination over the in-memory rows. Rows are sorted by
// the key columns so After cursors advance deterministically.
func (f *fakeReader) Page(_ context.Context, req contracts.PageRequest) (contracts.Page, error) {
	if err, ok := f.pageErr[req.Table]; ok {
		return contracts.Page{}, err
	}
	tbl, ok := f.tables[req.Table]
	if !ok {
		return contracts.Page{}, contracts.ErrNotFound
	}

	rows := make([]contracts.Row, len(tbl.rows))
	copy(rows, tbl.rows)

	less := func(a, b contracts.Row) bool {
		for _, k := range req.KeyColumns {
			va, vb := a[k], b[k]
			if va.Kind() != vb.Kind() {
				return va.Kind() < vb.Kind()
			}
			switch va.Kind() {
			case contracts.Null:
				return false
			case contracts.Text, contracts.Bytes, contracts.Date, contracts.LocalDateTime, contracts.Instant, contracts.Decimal:
				if va.Payload() != vb.Payload() {
					return va.Payload() < vb.Payload()
				}
			case contracts.Int:
				ia, _ := parseInt(va.Payload())
				ib, _ := parseInt(vb.Payload())
				if ia != ib {
					return ia < ib
				}
			case contracts.Uint:
				ua, _ := parseUint(va.Payload())
				ub, _ := parseUint(vb.Payload())
				if ua != ub {
					return ua < ub
				}
			case contracts.Float:
				fa, _ := parseFloat(va.Payload())
				fb, _ := parseFloat(vb.Payload())
				if fa != fb {
					return fa < fb
				}
			case contracts.Bool:
				if va.Payload() != vb.Payload() {
					return va.Payload() == "false"
				}
			}
		}
		return false
	}
	sort.Slice(rows, func(i, j int) bool { return less(rows[i], rows[j]) })

	// Apply After cursor
	if len(req.After) > 0 && len(req.After) == len(req.KeyColumns) {
		cut := -1
		for i, r := range rows {
			if keyGreater(r, req.KeyColumns, req.After) {
				cut = i
				break
			}
		}
		if cut >= 0 {
			rows = rows[cut:]
		} else {
			rows = nil
		}
	}

	limit := req.Limit
	if limit <= 0 {
		limit = 100
	}
	if len(rows) > limit {
		last := rows[limit-1]
		next := make([]contracts.Value, len(req.KeyColumns))
		for i, k := range req.KeyColumns {
			next[i] = last[k]
		}
		return contracts.Page{Rows: rows[:limit], Next: next, Done: false}, nil
	}
	return contracts.Page{Rows: rows, Next: nil, Done: true}, nil
}

func keyGreater(row contracts.Row, keys []string, after []contracts.Value) bool {
	for i, k := range keys {
		v := row[k]
		if v.Kind() != after[i].Kind() {
			return v.Kind() > after[i].Kind()
		}
		if v.Payload() != after[i].Payload() {
			switch v.Kind() {
			case contracts.Int:
				a, _ := parseInt(v.Payload())
				b, _ := parseInt(after[i].Payload())
				return a > b
			case contracts.Uint:
				a, _ := parseUint(v.Payload())
				b, _ := parseUint(after[i].Payload())
				return a > b
			case contracts.Float:
				a, _ := parseFloat(v.Payload())
				b, _ := parseFloat(after[i].Payload())
				return a > b
			default:
				return v.Payload() > after[i].Payload()
			}
		}
	}
	return false
}

func (f *fakeReader) Close() error { return nil }

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func mustValue(t *testing.T, kind contracts.Kind, raw string) contracts.Value {
	t.Helper()
	v, err := contracts.NewValue(kind, raw)
	if err != nil {
		t.Fatalf("NewValue(%v,%q): %v", kind, raw, err)
	}
	return v
}

func textV(s string) contracts.Value { return mustValue(&testing.T{}, contracts.Text, s) }

func peopleTable() contracts.TableRef {
	return contracts.TableRef{Database: "synthetic", Schema: "main", Table: "people"}
}

func peopleSchema() contracts.TableSchema {
	t := peopleTable()
	return contracts.TableSchema{
		Ref: t,
		Columns: []contracts.Column{
			{Ref: contracts.ColumnRef{TableRef: t, Column: "id"}, Type: contracts.Type{Kind: contracts.Int}},
			{Ref: contracts.ColumnRef{TableRef: t, Column: "email"}, Type: contracts.Type{Kind: contracts.Text}},
			{Ref: contracts.ColumnRef{TableRef: t, Column: "name"}, Type: contracts.Type{Kind: contracts.Text, Nullable: true}},
		},
		PrimaryKey: []string{"id"},
		Coverage:   contracts.SchemaCoverage{Columns: true, PrimaryKey: true},
	}
}

func peoplePlan() contracts.Plan {
	t := peopleTable()
	return contracts.Plan{
		Revision:         contracts.APIRevision,
		ID:               "plan-people",
		SourceSnapshotID: "snap-1",
		TargetID:         "tgt-1",
		SchemaDigest:     "schema-digest",
		ConfigDigest:     "config-digest",
		ScanComplete:     true,
		Tables: []contracts.TablePlan{{
			Table:      t,
			PrimaryKey: []string{"id"},
			Columns: []contracts.ColumnPlan{{
				Column:               contracts.ColumnRef{TableRef: t, Column: "email"},
				Type:                 contracts.Type{Kind: contracts.Text},
				Strategy:             contracts.StrategyRef{ID: "redact", Version: "v1"},
				Scope:                "email",
				NormalizationVersion: "typed-lexical-v1",
				KeyID:                "test-key",
			}},
		}},
	}
}

func rowWith(cols ...string) contracts.Row {
	r := make(contracts.Row, len(cols)/2)
	for i := 0; i+1 < len(cols); i += 2 {
		r[cols[i]] = textV(cols[i+1])
	}
	return r
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestCompileTimeAssertion(t *testing.T) {
	var _ contracts.Validator = New()
}

func TestValidate_ExactMatchPasses(t *testing.T) {
	tref := peopleTable()
	schema := peopleSchema()
	src := []contracts.Row{
		{"id": mustValue(t, contracts.Int, "1"), "email": textV("a@x.com"), "name": textV("Alice")},
		{"id": mustValue(t, contracts.Int, "2"), "email": textV("b@x.com"), "name": textV("Bob")},
	}
	tgt := []contracts.Row{
		{"id": mustValue(t, contracts.Int, "1"), "email": textV("###"), "name": textV("Alice")},
		{"id": mustValue(t, contracts.Int, "2"), "email": textV("###"), "name": textV("Bob")},
	}

	source, target := newFakeReader(), newFakeReader()
	source.addTable(tref, schema, src)
	target.addTable(tref, schema, tgt)

	v := New()
	rep, err := v.Validate(context.Background(), source, target, contracts.ValidateRequest{Plan: peoplePlan(), RowLimit: 10})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !rep.Passed(false) {
		t.Fatalf("expected pass, got issues=%v coverage=%+v", rep.Issues, rep.Coverage)
	}
	if !rep.Passed(true) {
		t.Fatalf("expected strict pass")
	}
	if !rep.Coverage.Complete {
		t.Fatal("coverage should be complete")
	}
}

func TestValidate_RowCountMismatch(t *testing.T) {
	tref := peopleTable()
	schema := peopleSchema()
	src := []contracts.Row{
		{"id": mustValue(t, contracts.Int, "1"), "email": textV("a@x.com")},
		{"id": mustValue(t, contracts.Int, "2"), "email": textV("b@x.com")},
	}
	tgt := []contracts.Row{
		{"id": mustValue(t, contracts.Int, "1"), "email": textV("###")},
	}

	source, target := newFakeReader(), newFakeReader()
	source.addTable(tref, schema, src)
	target.addTable(tref, schema, tgt)

	rep, err := New().Validate(context.Background(), source, target, contracts.ValidateRequest{Plan: peoplePlan(), RowLimit: 10})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if rep.Passed(false) {
		t.Fatal("row count mismatch should not pass")
	}
	if !hasIssue(rep, contracts.RowCountMismatch) {
		t.Fatalf("expected RowCountMismatch, got %v", codes(rep))
	}
}

func TestValidate_SourceOnlyKey(t *testing.T) {
	tref := peopleTable()
	schema := peopleSchema()
	src := []contracts.Row{
		{"id": mustValue(t, contracts.Int, "1"), "email": textV("a@x.com")},
		{"id": mustValue(t, contracts.Int, "2"), "email": textV("b@x.com")},
	}
	tgt := []contracts.Row{
		{"id": mustValue(t, contracts.Int, "1"), "email": textV("###")},
		{"id": mustValue(t, contracts.Int, "3"), "email": textV("###")},
	}

	source, target := newFakeReader(), newFakeReader()
	source.addTable(tref, schema, src)
	target.addTable(tref, schema, tgt)

	rep, _ := New().Validate(context.Background(), source, target, contracts.ValidateRequest{Plan: peoplePlan(), RowLimit: 10})
	if rep.Passed(false) {
		t.Fatal("key mismatch should not pass")
	}
	if !hasIssue(rep, contracts.KeyMismatch) {
		t.Fatalf("expected KeyMismatch, got %v", codes(rep))
	}
}

func TestValidate_TargetOnlyKey(t *testing.T) {
	tref := peopleTable()
	schema := peopleSchema()
	src := []contracts.Row{
		{"id": mustValue(t, contracts.Int, "1"), "email": textV("a@x.com")},
	}
	tgt := []contracts.Row{
		{"id": mustValue(t, contracts.Int, "1"), "email": textV("###")},
		{"id": mustValue(t, contracts.Int, "2"), "email": textV("###")},
	}

	source, target := newFakeReader(), newFakeReader()
	source.addTable(tref, schema, src)
	target.addTable(tref, schema, tgt)

	rep, _ := New().Validate(context.Background(), source, target, contracts.ValidateRequest{Plan: peoplePlan(), RowLimit: 10})
	if rep.Passed(false) {
		t.Fatal("target-only key should not pass")
	}
	if !hasIssue(rep, contracts.KeyMismatch) {
		t.Fatalf("expected KeyMismatch, got %v", codes(rep))
	}
}

func TestValidate_SameCountDifferentKey(t *testing.T) {
	tref := peopleTable()
	schema := peopleSchema()
	src := []contracts.Row{
		{"id": mustValue(t, contracts.Int, "1"), "email": textV("a@x.com")},
		{"id": mustValue(t, contracts.Int, "2"), "email": textV("b@x.com")},
	}
	tgt := []contracts.Row{
		{"id": mustValue(t, contracts.Int, "3"), "email": textV("###")},
		{"id": mustValue(t, contracts.Int, "4"), "email": textV("###")},
	}

	source, target := newFakeReader(), newFakeReader()
	source.addTable(tref, schema, src)
	target.addTable(tref, schema, tgt)

	rep, _ := New().Validate(context.Background(), source, target, contracts.ValidateRequest{Plan: peoplePlan(), RowLimit: 10})
	if rep.Passed(false) {
		t.Fatal("same count different keys should not pass")
	}
	if !hasIssue(rep, contracts.KeyMismatch) {
		t.Fatalf("expected KeyMismatch, got %v", codes(rep))
	}
}

func TestValidate_UnchangedSensitiveValue(t *testing.T) {
	tref := peopleTable()
	schema := peopleSchema()
	src := []contracts.Row{
		{"id": mustValue(t, contracts.Int, "1"), "email": textV("a@x.com")},
	}
	tgt := []contracts.Row{
		{"id": mustValue(t, contracts.Int, "1"), "email": textV("a@x.com")}, // unchanged!
	}

	source, target := newFakeReader(), newFakeReader()
	source.addTable(tref, schema, src)
	target.addTable(tref, schema, tgt)

	rep, _ := New().Validate(context.Background(), source, target, contracts.ValidateRequest{Plan: peoplePlan(), RowLimit: 10})
	if rep.Passed(false) {
		t.Fatal("unchanged sensitive value should not pass")
	}
	if !hasIssue(rep, contracts.UnchangedValue) {
		t.Fatalf("expected UnchangedValue, got %v", codes(rep))
	}
}

func TestValidate_MissingPrimaryKeyCoverage(t *testing.T) {
	tref := peopleTable()
	schema := peopleSchema()
	schema.Coverage.PrimaryKey = false
	rows := []contracts.Row{
		{"id": mustValue(t, contracts.Int, "1"), "email": textV("a@x.com")},
	}

	source, target := newFakeReader(), newFakeReader()
	source.addTable(tref, schema, rows)
	target.addTable(tref, schema, rows)

	rep, _ := New().Validate(context.Background(), source, target, contracts.ValidateRequest{Plan: peoplePlan(), RowLimit: 10})
	if !hasIssueStatus(rep, contracts.Warning) {
		t.Fatalf("expected Warning for missing PK coverage, got %v", rep.Issues)
	}
	if rep.Passed(true) {
		t.Fatal("warning should fail strict")
	}
	if rep.Passed(false) {
		t.Fatal("with only warning and no Fail issues, non-strict could pass; but here Complete may be true with warning — check")
	}
}

func TestValidate_SchemaMismatch(t *testing.T) {
	tref := peopleTable()
	srcSchema := peopleSchema()
	tgtSchema := peopleSchema()
	tgtSchema.Columns[1].Type.Kind = contracts.Bytes // email changed kind

	rows := []contracts.Row{
		{"id": mustValue(t, contracts.Int, "1"), "email": textV("a@x.com")},
	}

	source, target := newFakeReader(), newFakeReader()
	source.addTable(tref, srcSchema, rows)
	target.addTable(tref, tgtSchema, rows)

	rep, _ := New().Validate(context.Background(), source, target, contracts.ValidateRequest{Plan: peoplePlan(), RowLimit: 10})
	if rep.Passed(false) {
		t.Fatal("schema mismatch should not pass")
	}
	if !hasIssue(rep, contracts.SchemaMismatch) {
		t.Fatalf("expected SchemaMismatch, got %v", codes(rep))
	}
}

func TestValidate_InvalidRowLimit(t *testing.T) {
	_, err := New().Validate(context.Background(), newFakeReader(), newFakeReader(), contracts.ValidateRequest{Plan: peoplePlan(), RowLimit: 0})
	if !errors.Is(err, contracts.ErrInvalid) {
		t.Fatalf("expected ErrInvalid for RowLimit=0, got %v", err)
	}
}

func TestValidate_NilReader(t *testing.T) {
	_, err := New().Validate(context.Background(), nil, newFakeReader(), contracts.ValidateRequest{Plan: peoplePlan(), RowLimit: 1})
	if !errors.Is(err, contracts.ErrInvalid) {
		t.Fatalf("expected ErrInvalid for nil source, got %v", err)
	}
}

func TestValidate_ContextCancellation(t *testing.T) {
	tref := peopleTable()
	schema := peopleSchema()
	rows := []contracts.Row{
		{"id": mustValue(t, contracts.Int, "1"), "email": textV("a@x.com")},
	}
	source, target := newFakeReader(), newFakeReader()
	source.addTable(tref, schema, rows)
	target.addTable(tref, schema, rows)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := New().Validate(ctx, source, target, contracts.ValidateRequest{Plan: peoplePlan(), RowLimit: 10})
	if err == nil {
		t.Fatal("expected cancelled context to return error")
	}
}

func TestValidate_ReaderErrorPropagation(t *testing.T) {
	tref := peopleTable()
	schema := peopleSchema()
	rows := []contracts.Row{
		{"id": mustValue(t, contracts.Int, "1"), "email": textV("a@x.com")},
	}

	source, target := newFakeReader(), newFakeReader()
	source.addTable(tref, schema, rows)
	target.addTable(tref, schema, rows)
	source.countErr[tref] = errors.New("boom")

	rep, err := New().Validate(context.Background(), source, target, contracts.ValidateRequest{Plan: peoplePlan(), RowLimit: 10})
	if err != nil {
		t.Fatalf("reader error should be reported as issue, not returned: %v", err)
	}
	if !hasIssue(rep, contracts.DatabaseFailure) {
		t.Fatalf("expected DatabaseFailure, got %v", codes(rep))
	}
	if rep.Coverage.Complete {
		t.Fatal("reader error should keep coverage incomplete")
	}
}

func TestValidate_PlanNotMutated(t *testing.T) {
	tref := peopleTable()
	schema := peopleSchema()
	rows := []contracts.Row{
		{"id": mustValue(t, contracts.Int, "1"), "email": textV("a@x.com")},
	}
	source, target := newFakeReader(), newFakeReader()
	source.addTable(tref, schema, rows)
	target.addTable(tref, schema, rows)

	plan := peoplePlan()
	origTables := len(plan.Tables)
	origCols := len(plan.Tables[0].Columns)

	_, _ = New().Validate(context.Background(), source, target, contracts.ValidateRequest{Plan: plan, RowLimit: 10})

	if len(plan.Tables) != origTables || len(plan.Tables[0].Columns) != origCols {
		t.Fatal("Plan was mutated")
	}
}

func TestValidate_NoRawKeyOrValueInReport(t *testing.T) {
	tref := peopleTable()
	schema := peopleSchema()
	src := []contracts.Row{
		{"id": mustValue(t, contracts.Int, "1"), "email": textV("secret@x.com"), "name": textV("Alice")},
	}
	tgt := []contracts.Row{
		{"id": mustValue(t, contracts.Int, "1"), "email": textV("secret@x.com"), "name": textV("Alice")},
	}
	source, target := newFakeReader(), newFakeReader()
	source.addTable(tref, schema, src)
	target.addTable(tref, schema, tgt)

	rep, _ := New().Validate(context.Background(), source, target, contracts.ValidateRequest{Plan: peoplePlan(), RowLimit: 10})

	buf := new(strings.Builder)
	for _, iss := range rep.Issues {
		buf.WriteString(string(iss.Code))
		buf.WriteString(iss.Column.Column)
	}
	if strings.Contains(buf.String(), "secret") || strings.Contains(buf.String(), "Alice") {
		t.Fatalf("report leaked raw value: %q", buf.String())
	}
}

func TestValidate_EmptyTableCanPass(t *testing.T) {
	tref := peopleTable()
	schema := peopleSchema()
	source, target := newFakeReader(), newFakeReader()
	source.addTable(tref, schema, nil)
	target.addTable(tref, schema, nil)

	rep, err := New().Validate(context.Background(), source, target, contracts.ValidateRequest{Plan: peoplePlan(), RowLimit: 10})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !rep.Passed(false) {
		t.Fatalf("empty matching tables should pass, issues=%v", rep.Issues)
	}
	if rep.Coverage.Rows != 0 {
		t.Fatalf("expected 0 rows, got %d", rep.Coverage.Rows)
	}
}

func TestValidate_CoverageIncompleteNeverPasses(t *testing.T) {
	tref := peopleTable()
	schema := peopleSchema()
	rows := []contracts.Row{
		{"id": mustValue(t, contracts.Int, "1"), "email": textV("a@x.com")},
	}
	source, target := newFakeReader(), newFakeReader()
	source.addTable(tref, schema, rows)
	target.addTable(tref, schema, rows)
	source.describeErr[tref] = errors.New("conn refused")

	rep, _ := New().Validate(context.Background(), source, target, contracts.ValidateRequest{Plan: peoplePlan(), RowLimit: 10})
	if rep.Coverage.Complete {
		t.Fatal("describe error should keep coverage incomplete")
	}
	if rep.Passed(false) {
		t.Fatal("incomplete coverage must never pass")
	}
}

func TestValidate_CollationMismatchReturnsErrUnsupported(t *testing.T) {
	tref := peopleTable()
	srcSchema := peopleSchema()
	tgtSchema := peopleSchema()
	// set differing collation on the PK column
	for i := range srcSchema.Columns {
		if srcSchema.Columns[i].Ref.Column == "id" {
			srcSchema.Columns[i].Type.Collation = "binary"
		}
	}
	for i := range tgtSchema.Columns {
		if tgtSchema.Columns[i].Ref.Column == "id" {
			tgtSchema.Columns[i].Type.Collation = "utf8mb4_general_ci"
		}
	}
	rows := []contracts.Row{
		{"id": mustValue(t, contracts.Int, "1"), "email": textV("a@x.com")},
	}
	source, target := newFakeReader(), newFakeReader()
	source.addTable(tref, srcSchema, rows)
	target.addTable(tref, tgtSchema, rows)

	_, err := New().Validate(context.Background(), source, target, contracts.ValidateRequest{Plan: peoplePlan(), RowLimit: 10})
	if !errors.Is(err, contracts.ErrUnsupported) {
		t.Fatalf("expected ErrUnsupported for collation mismatch, got %v", err)
	}
}

func TestValidate_PaginationOverRowLimit(t *testing.T) {
	tref := peopleTable()
	schema := peopleSchema()
	var src, tgt []contracts.Row
	for i := 1; i <= 25; i++ {
		id := mustValue(t, contracts.Int, strconvItoa(i))
		src = append(src, contracts.Row{"id": id, "email": textV("a@x.com")})
		tgt = append(tgt, contracts.Row{"id": id, "email": textV("###")})
	}
	source, target := newFakeReader(), newFakeReader()
	source.addTable(tref, schema, src)
	target.addTable(tref, schema, tgt)

	// RowLimit=10 forces 3 pages; verifies keyset cursor traversal covers all rows.
	rep, err := New().Validate(context.Background(), source, target, contracts.ValidateRequest{Plan: peoplePlan(), RowLimit: 10})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !rep.Passed(false) {
		t.Fatalf("expected pass with pagination, issues=%v", rep.Issues)
	}
	if rep.Coverage.Rows != 25 {
		t.Fatalf("expected 25 rows, got %d", rep.Coverage.Rows)
	}
}

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

func hasIssue(rep contracts.ValidationReport, code contracts.IssueCode) bool {
	for _, iss := range rep.Issues {
		if iss.Code == code {
			return true
		}
	}
	return false
}

func hasIssueStatus(rep contracts.ValidationReport, status contracts.Status) bool {
	for _, iss := range rep.Issues {
		if iss.Status == status {
			return true
		}
	}
	return false
}

func codes(rep contracts.ValidationReport) []contracts.IssueCode {
	out := make([]contracts.IssueCode, len(rep.Issues))
	for i, iss := range rep.Issues {
		out[i] = iss.Code
	}
	return out
}

func strconvItoa(i int) string { return strconv.Itoa(i) }

func parseInt(s string) (int64, error)     { return strconv.ParseInt(s, 10, 64) }
func parseUint(s string) (uint64, error)   { return strconv.ParseUint(s, 10, 64) }
func parseFloat(s string) (float64, error) { return strconv.ParseFloat(s, 64) }
