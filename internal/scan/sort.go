package scan

import (
	"sort"

	"github.com/internal/rpcrecon/internal/model"
)

var severityOrder = map[model.Severity]int{
	model.SeverityCritical: 5,
	model.SeverityHigh:     4,
	model.SeverityMedium:   3,
	model.SeverityLow:      2,
	model.SeverityInfo:     1,
}

func sortFindings(fs []model.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if severityOrder[fs[i].Severity] != severityOrder[fs[j].Severity] {
			return severityOrder[fs[i].Severity] > severityOrder[fs[j].Severity]
		}
		if fs[i].Endpoint != fs[j].Endpoint {
			return fs[i].Endpoint < fs[j].Endpoint
		}
		return fs[i].Method < fs[j].Method
	})
}
