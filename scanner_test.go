package scanner

import "testing"

func TestScan_valid(t *testing.T) {
	t.Parallel()

	output, err := Scan("127.0.0.1", []int{22, 631})

	if err != nil {
		t.Fatalf("Unknown error occured while executing scan. Error: %s\n", err)
	}

	t.Logf("output of scan: %v", output)
}

func TestScan_scanAddress(t *testing.T) {
	t.Parallel()

	if _, err := Scan("", []int{22, 631}); err == nil {
		t.Fatal("empty scanAddress should return error")
	}
}

func TestScan_ports(t *testing.T) {
	t.Parallel()

	if _, err := Scan("127.0.0.1", []int{}); err == nil {
		t.Fatal("empty ports should return error")
	}
}

func TestArrayToString(t *testing.T) {
	expected := "22,631"

	if actual := arrayToString([]int{22, 631}); expected != actual {
		t.Fatalf("Expected: %s Actual: %s", expected, actual)
	}
}
