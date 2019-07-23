package scanner

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
)

// NMAPScan is the struct representation of an NMAP scan.
type NMAPScan struct {
	XMLName xml.Name `xml:"nmaprun"`
	Scanner string   `xml:"scanner,attr"`
	Host    Host     `xml:"host"`
}

// Host is a struct representation of a scanned NMAP host.
type Host struct {
	XMLName xml.Name `xml:"host"`
	Ports   Ports    `xml:"ports"`
}

// Ports is the struct representation of a scanned NMAP port.
type Ports struct {
	XMLName xml.Name `xml:"ports"`
	Ports   []Port   `xml:"port"`
}

// Status is the struct representaiton of a scanned NMAP ports status.
type Status struct {
	XMLName xml.Name `xml:"state"`
	State   string   `xml:"state,attr"`
}

// Service is the struct representation of a scanned NMAP hosts service output.
type Service struct {
	XMLName xml.Name `xml:"service"`
	Name    string   `xml:"name,attr"`
	Version string   `xml:"version,attr"`
	Product string   `xml:"product,attr"`
}

// Port is the struct representation of a scanned NMAP hosts port output.
type Port struct {
	XMLName  xml.Name `xml:"port"`
	Protocol string   `xml:"protocol,attr"`
	Number   string   `xml:"portid,attr"`
	Status   Status   `xml:"state"`
	Service  Service  `xml:"service"`
}

func arrayToString(array []int) string {
	return strings.Trim(strings.Join(strings.Fields(fmt.Sprint(array)), ","), "[]")
}

// Scan scans a given address on the given ports and returns results.
func Scan(scanAddress string, ports []int) (scanResults NMAPScan, err error) {
	if scanAddress == "" {
		return scanResults, errors.New("scanAddress can not be empty")
	}

	if len(ports) == 0 {
		return scanResults, errors.New("ports can not be empty")
	}

	nmapPath := os.Getenv("SCANNER_NMAP_BINARY_PATH")

	if nmapPath == "" {
		nmapPath, _ = exec.LookPath("nmap")
	}

	if nmapPath == "" {
		return scanResults, fmt.Errorf("could not find nmap at path: %s", nmapPath)
	}

	command := exec.Command(nmapPath, "-oX", ".output.xml", "-sS", "-sV", "-P0", "-p", arrayToString(ports), scanAddress)

	_, err = command.Output()

	if err != nil {
		return scanResults, fmt.Errorf("Error attempting to execute command. Could be permissions, are you running as root? Error: %s", err)
	}

	xmlOutput, err := os.Open(".output.xml")
	defer xmlOutput.Close()
	defer os.Remove(".output.xml")

	if err != nil {
		return scanResults, err
	}

	byteValue, err := ioutil.ReadAll(xmlOutput)
	if err != nil {
		return scanResults, err
	}

	xml.Unmarshal(byteValue, &scanResults)

	return scanResults, nil
}
