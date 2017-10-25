// Copyright © 2017 NAME HERE <EMAIL ADDRESS>
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
	"fmt"
	"github.com/kardianos/service"
	"github.com/spf13/cobra"
	"log"
)

var (
	command     string
	commandArgs []string
)

type program struct {
}

//Start the program
func (p *program) Start(s service.Service) error {
	return nil
}

//Stop the program
func (p *program) Stop(s service.Service) error {
	return nil
}

// serviceCmd represents the service command
var serviceCmd = &cobra.Command{
	Use:   "service install ... [install, uninstall, start, stop]",
	Short: "Use this command to add a service for a command",
	Long:  `Use this command to add a service for a command`,
	Run: func(cmd *cobra.Command, args []string) {

		commandArgs = append([]string{command}, commandArgs...)
		svcConfig := &service.Config{
			Name:        "capcap",
			DisplayName: "capcap",
			Arguments:   commandArgs,
			Description: "Capcap " + command + " service",
		}
		prg := &program{}

		s, err := service.New(prg, svcConfig)
		if err != nil {
			log.Println(err.Error())
			return
		}
		if len(args) == 0 {
			fmt.Println("install, uninstall, start, stop")
			return
		}
		err = service.Control(s, args[0])
		if err != nil {
			fmt.Println(err.Error())
		}
	},
}

func init() {
	RootCmd.AddCommand(serviceCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// serviceCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// serviceCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	serviceCmd.Flags().StringVarP(&command, "command", "c", "watch", "command to run")
	serviceCmd.Flags().StringArrayVarP(&commandArgs, "args", "a", []string{}, "specify command args")
}
