package capcap

import (
	"compress/gzip"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"
)

type pcapWrapper interface {
	WritePacket(ci gopacket.CaptureInfo, data []byte) error
	Close() error
}

type regularPcapWrapper struct {
	io.WriteCloser
	*pcapgo.Writer
}

type gzippedPcapWrapper struct {
	w io.WriteCloser
	z *gzip.Writer
	*pcapgo.Writer
}

func (wrapper *gzippedPcapWrapper) Close() error {
	gzerr := wrapper.z.Close()
	ferr := wrapper.w.Close()

	if gzerr != nil {
		return gzerr
	}
	if ferr != nil {
		return ferr
	}

	return nil
}

func openPcap(baseFilename string, conf *Conf) (pcapWrapper, error) {
	if conf.WriteCompressed {
		baseFilename = baseFilename + ".gz"
	}
	log.Printf("Opening new pcap file %s", baseFilename)
	outf, err := os.Create(baseFilename)
	if err != nil {
		return nil, err
	}
	if conf.WriteCompressed {
		outgz := gzip.NewWriter(outf)
		pcapWriter := pcapgo.NewWriter(outgz)
		pcapWriter.WriteFileHeader(65536, layers.LinkTypeEthernet) // new file, must do this.
		return &gzippedPcapWrapper{outf, outgz, pcapWriter}, nil
	} else {
		pcapWriter := pcapgo.NewWriter(outf)
		pcapWriter.WriteFileHeader(65536, layers.LinkTypeEthernet) // new file, must do this.
		return &regularPcapWrapper{outf, pcapWriter}, nil
	}
}

//renamePcap renames the 'current' file to
//writeOutputPath/yyy/mm/dd/yyyy-mm-ddThh-mm-ss.pcap.gz

func renamePcap(tempName, outputPath string, writeCompressed bool) error {
	// datePart := time.Now().Format("2006/01/02/2006-01-02T15-04-05.pcap")
	datePart := time.Now().Format("2006-01-02T15-04-05.pcap")
	if writeCompressed {
		datePart = datePart + ".gz"
		tempName = tempName + ".gz"
	}

	newName := filepath.Join(outputPath, "rotated", datePart)
	//Ensure the directori exists
	if err := os.MkdirAll(filepath.Dir(newName), 0777); err != nil {
		return err
	}
	err := os.Rename(tempName, newName)

	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil {
		log.Printf("moved %s to %s", tempName, newName)
	}
	return nil
}
