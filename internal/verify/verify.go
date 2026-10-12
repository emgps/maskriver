// Package verify implements schema, row-count, key-aligned, and value-change
// validation against a frozen Plan using only contracts.Reader.
//
// Reports contain only Status/IssueCode, location, and counts. No raw key or
// sample value is emitted. Coverage.Complete defaults to false and is set true
// only when every planned table was read and compared without reader errors.
package verify

import (
	"context"
	"strconv"
	"strings"

	"github.com/haoyuehx/maskriver/pkg/contracts"
)

// New returns a Validator that compares source and target readers against a
// frozen Plan. It performs no I/O of its own beyond the supplied readers.
func New() contracts.Validator { return &validator{} }

type validator struct{}

// Validate compares source and target for every table in the Plan.
//
//   - Schema element comparison (column kinds, nullability, dimensions, PK).
//   - Row-count comparison.
//   - Bidirectional key-set comparison (source-only and target-only keys fail).
//   - Per-key value-change verification for every column listed in the Plan.
//
// Reader errors are surfaced as DatabaseFailure issues and keep Coverage.Complete
// false. Mismatches produce Fail issues. Missing PK coverage is a Warning.
func (v *validator) Validate(ctx context.Context, source, target contracts.Reader, req contracts.ValidateRequest) (contracts.ValidationReport, error) {
	report := contracts.ValidationReport{
		PlanID:   req.Plan.ID,
		Coverage: contracts.Coverage{Complete: false},
	}

	if source == nil || target == nil {
		return report, contracts.ErrInvalid
	}
	if err := req.Plan.ValidateShape(); err != nil {
		return report, err
	}
	if req.RowLimit <= 0 {
		return report, contracts.ErrInvalid
	}

	var (
		totalRows int64
		totalCols int64
		complete  = true
	)

	for _, tp := range req.Plan.Tables {
		select {
		case <-ctx.Done():
			return report, ctx.Err()
		default:
		}

		tableCols := int64(len(tp.Columns))

		srcSchema, err := source.Describe(ctx, tp.Table)
		if err != nil {
			report.Issues = append(report.Issues, contracts.Issue{Status: contracts.Error, Code: contracts.DatabaseFailure, Count: 1})
			complete = false
			continue
		}
		tgtSchema, err := target.Describe(ctx, tp.Table)
		if err != nil {
			report.Issues = append(report.Issues, contracts.Issue{Status: contracts.Error, Code: contracts.DatabaseFailure, Count: 1})
			complete = false
			continue
		}

		if !schemaElementEqual(srcSchema, tgtSchema) {
			report.Issues = append(report.Issues, contracts.Issue{Status: contracts.Fail, Code: contracts.SchemaMismatch, Count: 1})
			continue
		}
		if !srcSchema.Coverage.PrimaryKey || !tgtSchema.Coverage.PrimaryKey {
			report.Issues = append(report.Issues, contracts.Issue{Status: contracts.Warning, Code: contracts.InsufficientEvidence, Count: 1})
			continue
		}

		// A differing collation on a key column makes lexical key alignment
		// unsafe; refuse rather than misjudging.
		if collationsDifferOnKey(srcSchema, tgtSchema, tp.PrimaryKey) {
			return report, contracts.ErrUnsupported
		}

		srcCount, err := source.Count(ctx, tp.Table)
		if err != nil {
			report.Issues = append(report.Issues, contracts.Issue{Status: contracts.Error, Code: contracts.DatabaseFailure, Count: 1})
			complete = false
			continue
		}
		tgtCount, err := target.Count(ctx, tp.Table)
		if err != nil {
			report.Issues = append(report.Issues, contracts.Issue{Status: contracts.Error, Code: contracts.DatabaseFailure, Count: 1})
			complete = false
			continue
		}
		if srcCount != tgtCount {
			diff := srcCount - tgtCount
			if diff < 0 {
				diff = -diff
			}
			report.Issues = append(report.Issues, contracts.Issue{Status: contracts.Fail, Code: contracts.RowCountMismatch, Count: diff})
		}

		cols := columnList(tp)

		srcRows, srcKeys, err := readAllRows(ctx, source, tp.Table, cols, tp.PrimaryKey, req.RowLimit)
		if err != nil {
			report.Issues = append(report.Issues, contracts.Issue{Status: contracts.Error, Code: contracts.DatabaseFailure, Count: 1})
			complete = false
			continue
		}

		tgtKeys, ok := compareTarget(ctx, target, tp, cols, req.RowLimit, srcRows, &report)
		if !ok {
			complete = false
			continue
		}

		for key := range srcKeys {
			if !tgtKeys[key] {
				report.Issues = append(report.Issues, contracts.Issue{Status: contracts.Fail, Code: contracts.KeyMismatch, Count: 1})
			}
		}

		totalRows += srcCount
		totalCols += tableCols
	}

	report.Coverage.Tables = int64(len(req.Plan.Tables))
	report.Coverage.Columns = totalCols
	report.Coverage.Rows = totalRows
	report.Coverage.Complete = complete

	return report, nil
}

func columnList(tp contracts.TablePlan) []string {
	cols := make([]string, 0, len(tp.PrimaryKey)+len(tp.Columns))
	seen := make(map[string]bool, len(tp.PrimaryKey)+len(tp.Columns))
	for _, k := range tp.PrimaryKey {
		if !seen[k] {
			seen[k] = true
			cols = append(cols, k)
		}
	}
	for _, cp := range tp.Columns {
		c := cp.Column.Column
		if !seen[c] {
			seen[c] = true
			cols = append(cols, c)
		}
	}
	return cols
}

func readAllRows(ctx context.Context, r contracts.Reader, table contracts.TableRef, cols, pk []string, limit int64) (map[string]contracts.Row, map[string]bool, error) {
	rows := make(map[string]contracts.Row)
	keys := make(map[string]bool)
	var after []contracts.Value
	for {
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		default:
		}
		page, err := r.Page(ctx, contracts.PageRequest{Table: table, Columns: cols, KeyColumns: pk, After: after, Limit: int(limit)})
		if err != nil {
			return nil, nil, err
		}
		for _, row := range page.Rows {
			key := serializeKey(row, pk)
			rows[key] = row
			keys[key] = true
		}
		if page.Done {
			break
		}
		after = page.Next
	}
	return rows, keys, nil
}

// compareTarget streams target pages, flags target-only keys, and verifies that
// every planned column changed for keys present in both readers.
func compareTarget(ctx context.Context, target contracts.Reader, tp contracts.TablePlan, cols []string, limit int64, srcRows map[string]contracts.Row, report *contracts.ValidationReport) (map[string]bool, bool) {
	tgtKeys := make(map[string]bool)
	var after []contracts.Value
	for {
		select {
		case <-ctx.Done():
			return tgtKeys, false
		default:
		}
		page, err := target.Page(ctx, contracts.PageRequest{Table: tp.Table, Columns: cols, KeyColumns: tp.PrimaryKey, After: after, Limit: int(limit)})
		if err != nil {
			report.Issues = append(report.Issues, contracts.Issue{Status: contracts.Error, Code: contracts.DatabaseFailure, Count: 1})
			return tgtKeys, false
		}
		for _, row := range page.Rows {
			key := serializeKey(row, tp.PrimaryKey)
			tgtKeys[key] = true
			srcRow, ok := srcRows[key]
			if !ok {
				report.Issues = append(report.Issues, contracts.Issue{Status: contracts.Fail, Code: contracts.KeyMismatch, Count: 1})
				continue
			}
			for _, cp := range tp.Columns {
				srcVal := srcRow[cp.Column.Column]
				tgtVal := row[cp.Column.Column]
				if srcVal == tgtVal && !srcVal.IsNull() {
					report.Issues = append(report.Issues, contracts.Issue{Status: contracts.Fail, Code: contracts.UnchangedValue, Column: cp.Column, Count: 1})
				}
			}
		}
		if page.Done {
			break
		}
		after = page.Next
	}
	return tgtKeys, true
}

// serializeKey produces an unambiguous, length-prefixed string for a composite
// key. It is used only as an internal map key and never appears in reports.
func serializeKey(row contracts.Row, pk []string) string {
	var b strings.Builder
	for _, col := range pk {
		v := row[col]
		b.WriteString(strconv.Itoa(int(v.Kind())))
		b.WriteByte(':')
		b.WriteString(strconv.Itoa(len(v.Payload())))
		b.WriteByte(':')
		b.WriteString(v.Payload())
		b.WriteByte('|')
	}
	return b.String()
}

func schemaElementEqual(a, b contracts.TableSchema) bool {
	if len(a.Columns) != len(b.Columns) {
		return false
	}
	am := make(map[string]contracts.Type, len(a.Columns))
	for _, c := range a.Columns {
		am[c.Ref.Column] = c.Type
	}
	for _, c := range b.Columns {
		t, ok := am[c.Ref.Column]
		if !ok {
			return false
		}
		if t.Kind != c.Type.Kind ||
			t.Nullable != c.Type.Nullable ||
			t.Length != c.Type.Length ||
			t.Precision != c.Type.Precision ||
			t.Scale != c.Type.Scale {
			return false
		}
	}
	if len(a.PrimaryKey) != len(b.PrimaryKey) {
		return false
	}
	for i := range a.PrimaryKey {
		if a.PrimaryKey[i] != b.PrimaryKey[i] {
			return false
		}
	}
	return true
}

func collationsDifferOnKey(a, b contracts.TableSchema, pk []string) bool {
	ac := make(map[string]string, len(a.Columns))
	for _, c := range a.Columns {
		ac[c.Ref.Column] = c.Type.Collation
	}
	for _, c := range b.Columns {
		for _, k := range pk {
			if c.Ref.Column == k && ac[k] != c.Type.Collation {
				return true
			}
		}
	}
	return false
}
