package horst

import (
	"encoding/csv"
	"strings"
	"testing"
)

var aLine = "2025-02-11 08:10:39.505813 +0000, BEACON, 8c:3b:ad:f0:94:6e, ff:ff:ff:ff:ff:ff, 8c:3b:ad:f0:94:6e, 0, -49, 194, 60, 2412, 000002ad9e7e6061, EXHO2, 1, 1, 1, 0, 1, 0.0.0.0, 0.0.0.0"

func TestParseHorstFields(t *testing.T) {
	r := csv.NewReader(strings.NewReader(aLine))
	vals, err := r.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	p, err := ParseHorstFields(vals[0])
	if err != nil {
		t.Fatal(err)
	}
	t.Log(p)
}
