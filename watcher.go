package capcap

import (
	"fmt"
	"github.com/google/gopacket/pcap"
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

// mustSniff tries to sniff a device or waits for a device to be available then sniff
func mustSniff(iface string, worker int, writerchan chan PcapFrame, conf *Conf) (*pcap.Handle, error) {
	handle, err := openHandle(iface, conf)
	if err != nil {
		log.Println("unable to sniff", err.Error())
		// every 5 seconds try to reconnect
		<-time.After(5 * time.Second)
		return mustSniff(iface, worker, writerchan, conf)
	}
	log.Println("opened " + iface + " handle")
	return handle, nil
}

func handleInterface(iface string, worker int, pcapWriterChan chan PcapFrame, conf *Conf) {
	handle, _ := mustSniff(iface, worker, pcapWriterChan, conf)
	defer handle.Close()
	err := doSniff(handle, iface, worker, pcapWriterChan, conf)
	if err != nil {
		log.Println(err.Error())
		if strings.HasPrefix(err.Error(), "reconnect") {
			handle.Close()
			go handleInterface(iface, worker, pcapWriterChan, conf)
		}
	}
	log.Println("handleInterface finished")
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
			go handleInterface(iface, worker, pcapWriterChan, conf)
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
