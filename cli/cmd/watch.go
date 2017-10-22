// Copyright © 2017 osiloke emoekpere <me@osiloke.com>
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"github.com/osiloke/capcap"
	"github.com/spf13/cobra"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var (
	ifaces             []string
	workerCount        int
	filter             string
	packetTimeInterval time.Duration
	flowTimeout        time.Duration
	flowByteCutoff     uint
	flowPacketCutoff   uint
	writeOutputPath    string
	writeCompressed    bool

	rotationInterval time.Duration
)

// watchCmd represents the watch command
var watchCmd = &cobra.Command{
	Use:   "watch",
	Short: "Watch an interface",
	Long:  `Watch an interface.`,
	Run: func(cmd *cobra.Command, args []string) {
		signalChan := make(chan os.Signal, 1)

		signal.Notify(signalChan,
			os.Interrupt,
			os.Kill,
			syscall.SIGTERM,
		)
		done := make(chan bool, 1)
		complete := make(chan bool, 1)
		go capcap.Watch(done, complete, workerCount, &capcap.Conf{
			"",
			ifaces,
			filter,
			packetTimeInterval,
			flowTimeout,
			flowByteCutoff,
			flowPacketCutoff,
			writeOutputPath,
			writeCompressed,
			rotationInterval,
		})
	OUTER:
		for {
			select {
			case <-signalChan:
				println("signal received")
				capcap.Stop(done, complete)
				break OUTER
			}
		}
	},
}

func init() {
	RootCmd.AddCommand(watchCmd)
	watchCmd.Flags().StringArrayVarP(&ifaces, "interfaces", "i", []string{"eth0"}, "interfaces to watch")
	watchCmd.Flags().IntVarP(&workerCount, "worker-count", "w", 1, "worker count")
	watchCmd.Flags().StringVarP(&filter, "filter", "f", "ip or ip6", "bpf filter")
	watchCmd.Flags().DurationVarP(&packetTimeInterval, "timeinterval", "l", 5*time.Second, "Interval between cleanups")
	watchCmd.Flags().DurationVarP(&flowTimeout, "flowtimeout", "t", 5*time.Second, "Flow inactivity timeout")
	watchCmd.Flags().UintVarP(&flowByteCutoff, "bytecutoff", "b", 8192, "Cut off flows after this many bytes")
	watchCmd.Flags().UintVarP(&flowPacketCutoff, "packetcutoff", "o", 100, "Cut off flows after this many packets")
	watchCmd.Flags().StringVarP(&writeOutputPath, "write", "u", "out", "Output path is $writeOutputPath/yyyy/mm/dd/ts.pcap")
	watchCmd.Flags().BoolVarP(&writeCompressed, "compress", "c", false, "gzip pcaps as they are written")
	watchCmd.Flags().DurationVarP(&rotationInterval, "rotationinterval", "r", 300*time.Second, "Interval between pcap rotations")

}
