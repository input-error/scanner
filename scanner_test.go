package scanner

import "testing"

func TestScan(t *testing.T) {
	t.Parallel()

	output, err := Scan("127.0.0.1", "22,631")

	t.Logf("output of scan: %v", output)
	if err != nil {
		t.Fatalf("Unknown error occured while executing scan. Error: %s\n", err)
	}
}
