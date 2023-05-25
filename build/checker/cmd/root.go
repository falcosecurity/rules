package cmd

import (
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "checker",
	Short: "General-purpose tool for sanity checks around Falco rules files",
	Long:  "",
}

// Execute adds all child commands to the root command.
func Execute() {
	logrus.SetLevel(logrus.DebugLevel)
	cobra.CheckErr(rootCmd.Execute())
}
