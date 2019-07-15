package scanner

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
)

type NMAPScan struct {
	XMLName xml.Name `xml:"nmaprun"`
	Scanner string   `xml:"scanner,attr"`
	Host    Host     `xml:"host"`
}

type Host struct {
	XMLName xml.Name `xml:"host"`
	Ports   Ports    `xml:"ports"`
}

type Ports struct {
	XMLName xml.Name `xml:"ports"`
	Ports   []Port   `xml:"port"`
}

type Status struct {
	XMLName xml.Name `xml:"state"`
	State   string   `xml:"state,attr"`
}

type Service struct {
	XMLName xml.Name `xml:"service"`
	Name    string   `xml:"name,attr"`
	Version string   `xml:"version,attr"`
	Product string   `xml:"product,attr"`
}

type Port struct {
	XMLName  xml.Name `xml:"port"`
	Protocol string   `xml:"protocol,attr"`
	Number   string   `xml:"portid,attr"`
	Status   Status   `xml:"state"`
	Service  Service  `xml:"service"`
}

func Scan(scanAddress string, ports string) (scanResults NMAPScan, err error) {
	if scanAddress == "" {
		return scanResults, errors.New("scanAddress can not be empty!")
	}

	nmapPath := os.Getenv("SCANNER_NMAP_BINARY_PATH")

	if nmapPath == "" {
		nmapPath, _ = exec.LookPath("nmap")
	}

	if nmapPath == "" {
		return scanResults, errors.New(fmt.Sprintf("Could not find nmap at path: %s", nmapPath))
	}

	command := exec.Command(nmapPath, "-oX", "/tmp/output.xml", "-sS", "-sV", "-P0", "-p", ports, scanAddress)

	_, err = command.Output()

	if err != nil {
		return scanResults, errors.New(fmt.Sprintf("Error attempting to execute command. Error: %s", err))
	}

	xmlOutput, err := os.Open("/tmp/output.xml")
	defer xmlOutput.Close()
	defer os.Remove("/tmp/output.xml")

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
