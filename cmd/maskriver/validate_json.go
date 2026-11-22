package main

// Machine-readable validate output (issue #115).
//
// `validate --format json` lets an automated acceptance run read the strict
// validation verdict and its evidence without parsing human text. The report is a
// deliberate projection of contracts.ValidationReport, not a serialization of it:
// every field below is listed explicitly, so a field added to the contract later
// can never reach the report by accident.
//
// The projection carries codes, statuses and counts only. Issues are reduced to
// their code, status and count, which keeps table names, column names, values,
// primary keys, DSNs, seeds and key material out of a machine-readable artifact
// exactly as the text summary keeps them out of the human one. Detail that a
// human needs stays on stderr; stdout stays a single parseable object.

import (
	"encoding/json"
	"io"

	"github.com/haoyuehx/maskriver/pkg/contracts"
)

// validateJSONSchemaVersion names the JSON report contract. A consumer that does
// not recognise this version must refuse the report rather than guess at it.
const validateJSONSchemaVersion = "maskriver.validate.v1"

// Overall result values. They are the machine counterpart of the exit code:
// pass means exit 0, while fail and error both mean a non-zero exit.
const (
	validateStatusPass  = "pass"
	validateStatusFail  = "fail"
	validateStatusError = "error"
)

// outputState records the output contract one invocation asked for and whether it
// has been satisfied yet. It is per invocation, so the recursive help call in
// main.go never inherits a JSON requirement.
type outputState struct {
	// json is true once the validate command accepted --format json.
	json bool
	// emitted is true once the report object reached stdout.
	emitted bool
	// strict is the --strict value the verdict is computed with, recorded so an
	// error report can state the setting it failed under.
	strict bool
}

// validateJSONReport is the whole stdout payload of validate --format json.
type validateJSONReport struct {
	SchemaVersion string               `json:"schema_version"`
	Status        string               `json:"status"`
	Complete      bool                 `json:"complete"`
	Strict        bool                 `json:"strict"`
	Coverage      validateJSONCoverage `json:"coverage"`
	Issues        []validateJSONIssue  `json:"issues"`
}

// validateJSONCoverage mirrors the counting evidence of one validation.
type validateJSONCoverage struct {
	Tables  int64 `json:"tables"`
	Columns int64 `json:"columns"`
	Rows    int64 `json:"rows"`
}

// validateJSONIssue is one finding reduced to what the text summary already
// discloses: its severity, its frozen code and how many rows it covers.
type validateJSONIssue struct {
	Status string `json:"status"`
	Code   string `json:"code"`
	Count  int64  `json:"count"`
}

// validateJSONFromReport projects one completed validation into the report. passed
// is the verdict validationPassed produced for this same report, so the JSON
// status can not disagree with the exit code the command returns.
func validateJSONFromReport(report contracts.ValidationReport, strict, passed bool) validateJSONReport {
	out := validateJSONReport{
		SchemaVersion: validateJSONSchemaVersion,
		Status:        validateStatusFail,
		Complete:      report.Coverage.Complete,
		Strict:        strict,
		Coverage: validateJSONCoverage{
			Tables:  report.Coverage.Tables,
			Columns: report.Coverage.Columns,
			Rows:    report.Coverage.Rows,
		},
		// An always-present array keeps "no issues" distinguishable from "the
		// report is a placeholder" and spares every consumer a nil check.
		Issues: make([]validateJSONIssue, 0, len(report.Issues)),
	}
	if passed {
		out.Status = validateStatusPass
	}
	for _, issue := range report.Issues {
		out.Issues = append(out.Issues, validateJSONIssue{
			Status: issueStatusName(issue.Status),
			Code:   issueCodeName(issue.Code),
			Count:  issue.Count,
		})
	}
	return out
}

// failedValidateJSONReport is the report for an invocation that never reached a
// verdict. Nothing was proven complete and no issue was observed, so the evidence
// fields are empty rather than invented; the failure reason itself stays on
// stderr as the existing sanitized diagnostic.
func failedValidateJSONReport(strict bool) validateJSONReport {
	return validateJSONReport{
		SchemaVersion: validateJSONSchemaVersion,
		Status:        validateStatusError,
		Strict:        strict,
		Issues:        []validateJSONIssue{},
	}
}

// emitValidateJSON writes exactly one JSON object followed by a newline. The
// struct is fixed, so encoding can not fail; a write failure is not retried,
// because writing a second object to the same stream would break the one-object
// contract the caller already promised.
func emitValidateJSON(w io.Writer, report validateJSONReport) {
	raw, err := json.Marshal(report)
	if err != nil {
		return
	}
	_, _ = w.Write(append(raw, '\n'))
}

// issueStatusName spells a contract status, so the report never depends on the
// numeric values of contracts.Status.
func issueStatusName(status contracts.Status) string {
	switch status {
	case contracts.Pass:
		return "pass"
	case contracts.Fail:
		return "fail"
	case contracts.Warning:
		return "warning"
	case contracts.Error:
		return "error"
	default:
		return "unknown"
	}
}

// issueCodeName spells a frozen issue code. An unset code is reported as
// "unknown" instead of an empty string, so a required field is never blank.
func issueCodeName(code contracts.IssueCode) string {
	if code == "" {
		return "unknown"
	}
	return string(code)
}
