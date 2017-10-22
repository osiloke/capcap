package capcap

import (
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"time"
)

func Stop(done, complete chan bool) {
	done <- true
	select {
	case <-time.After(5 * time.Second):
		return
	case <-complete:
		return
	}
}
func Watch(done, complete chan bool, workerCount int, conf *Conf) {
	var (
		writeOutputPath  = conf.WriteOutputPath
		rotationInterval = conf.RotationInterval
	)
	ifacesName := strings.Join(conf.Iface, "_")
	currentFileName := filepath.Join(conf.WriteOutputPath, fmt.Sprintf("%s_current.pcap.tmp", ifacesName))
	pcapWriterChan := make(chan PcapFrame, 500000)

	for _, iface := range conf.Iface {
		log.Printf("Starting capture on %s with %d workers", iface, workerCount)
		for worker := 0; worker < workerCount; worker++ {
			go doSniff(iface, worker, pcapWriterChan, conf)
		}
	}

	rotationTicker := time.NewTicker(rotationInterval)

	//Rename any leftover pcap files from a previous run
	renamePcap(currentFileName, conf.WriteOutputPath, conf.WriteCompressed)

	var pcapWriter pcapWrapper
	pcapWriter, err := openPcap(currentFileName, conf)
	if err != nil {
		log.Fatal("Error opening pcap", err)
	}
OUTER:
	for {
		select {
		case pcf := <-pcapWriterChan:
			err := pcapWriter.WritePacket(pcf.ci, pcf.data)
			if err != nil {
				pcapWriter.Close()
				log.Fatal("Error writing output pcap", err)
			}

		case <-rotationTicker.C:
			log.Print("Rotating")
			//FIXME: refactor/wrap the open/close/rename code?
			err = pcapWriter.Close()
			if err != nil {
				log.Fatal("Error closing pcap", err)
			}
			err = renamePcap(currentFileName, writeOutputPath, conf.WriteCompressed)
			if err != nil {
				log.Fatal("Error renaming pcap", err)
			}
			pcapWriter, err = openPcap(currentFileName, conf)
			if err != nil {
				log.Fatal("Error opening pcap", err)
			}
		case <-done:
			log.Print("closing watcher")
			err = pcapWriter.Close()
			if err != nil {
				log.Fatal("Error Closing", err)
			}
			err = renamePcap(currentFileName, writeOutputPath, conf.WriteCompressed)
			if err != nil {
				log.Fatal("Error renaming pcap", err)
			}
			break OUTER
		}
	}
	complete <- true
	log.Println("stopped watcher")
}

type Watcher struct {
	done chan bool
}
