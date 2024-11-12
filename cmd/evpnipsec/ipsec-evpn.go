// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2022-2023 Dell Inc, or its subsidiaries.

// Package evpnipsec implements the ipsec related CLI commands
package evpnipsec

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/opiproject/godpu/cmd/common"
	"github.com/opiproject/godpu/evpnipsec"
	"github.com/spf13/cobra"
)

// AddSaCommand Add Sa Command
func AddSaCommand() *cobra.Command {
	var (
		src          string
		dst          string
		spi          uint32
		proto        int32
		ifID         uint32
		reqid        uint32
		mode         int32
		intrface     string
		encAlg       int32
		encKey       string
		intAlg       int32
		intKey       string
		replayWindow uint32
		tfc          uint32
		encap        int32
		esn          int32
		copyDf       int32
		copyEcn      int32
		copyDscp     int32
		initiator    int32
		inbound      int32
		update       int32
	)

	var cmd = &cobra.Command{
		Use:     "add-sa",
		Aliases: []string{"c"},
		Short:   "add-sa functionality",
		Args:    cobra.NoArgs,
		Run: func(c *cobra.Command, _ []string) {
			tlsFiles, err := c.Flags().GetString(common.TLSFiles)
			cobra.CheckErr(err)

			addr, err := c.Flags().GetString(common.AddrCmdLineArg)
			cobra.CheckErr(err)

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			IPSecEvpnClient, err := evpnipsec.NewIPSecClient(addr, tlsFiles)
			if err != nil {
				log.Printf("error creating logical bridge: %s\n", err)
			}
			data, err := IPSecEvpnClient.AddSA(ctx,
				src, dst, spi, proto, ifID, reqid, mode, intrface, encAlg, encKey, intAlg, intKey,
				replayWindow, tfc, encap, esn, copyDf, copyEcn, copyDscp, initiator, inbound, update,
			)
			if err != nil {
				log.Printf("error creating logical bridge: %s\n", err)
			}
			fmt.Println("AddSAReq marshaled successfully:", data)
		},
	}

	cmd.Flags().StringVar(&src, "src", "", "Source address or hostname")
	cmd.Flags().StringVar(&dst, "dst", "", "Destination address or hostname")
	cmd.Flags().Uint32Var(&spi, "spi", 0, "SPI")
	cmd.Flags().Int32Var(&proto, "proto", 0, "Protocol (ESP/AH)")
	cmd.Flags().Uint32Var(&ifID, "if_id", 0, "Interface ID")
	cmd.Flags().Uint32Var(&reqid, "reqid", 0, "Reqid")
	cmd.Flags().Int32Var(&mode, "mode", 0, "Mode (tunnel, transport...)")
	cmd.Flags().StringVar(&intrface, "interface", "", "Network interface restricting policy")
	cmd.Flags().Int32Var(&encAlg, "enc_alg", 0, "Encryption algorithm")
	cmd.Flags().StringVar(&encKey, "enc_key", "", "Encryption key")
	cmd.Flags().Int32Var(&intAlg, "int_alg", 0, "Integrity protection algorithm")
	cmd.Flags().StringVar(&intKey, "int_key", "", "Integrity protection key")
	cmd.Flags().Uint32Var(&replayWindow, "replay_window", 0, "Anti-replay window size")
	cmd.Flags().Uint32Var(&tfc, "tfc", 0, "Traffic Flow Confidentiality padding")
	cmd.Flags().Int32Var(&encap, "encap", 0, "Enable UDP encapsulation for NAT traversal")
	cmd.Flags().Int32Var(&esn, "esn", 0, "Mark the SA should apply to packets after processing")
	cmd.Flags().Int32Var(&copyDf, "copy_df", 0, "Copy the DF bit to the outer IPv4 header in tunnel mode")
	cmd.Flags().Int32Var(&copyEcn, "copy_ecn", 0, "Copy the ECN header field to/from the outer header")
	cmd.Flags().Int32Var(&copyDscp, "copy_dscp", 0, "Copy the DSCP header field to/from the outer header")
	cmd.Flags().Int32Var(&initiator, "initiator", 0, "TRUE if initiator of the exchange creating the SA")
	cmd.Flags().Int32Var(&inbound, "inbound", 0, "TRUE if this is an inbound SA")
	cmd.Flags().Int32Var(&update, "update", 0, "TRUE if an SPI has already been allocated for this SA")

	return cmd
}

// DelSaCommand tests the  del SA
func DelSaCommand() *cobra.Command {
	var (
		src   string
		dst   string
		spi   uint32
		proto int32
		ifID  uint32
	)

	var cmd = &cobra.Command{
		Use:     "Del-sa",
		Aliases: []string{"c"},
		Short:   "add-sa functionality",
		Args:    cobra.NoArgs,
		Run: func(c *cobra.Command, _ []string) {
			tlsFiles, err := c.Flags().GetString(common.TLSFiles)
			cobra.CheckErr(err)

			addr, err := c.Flags().GetString(common.AddrCmdLineArg)
			cobra.CheckErr(err)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			IPSecEvpnClient, err := evpnipsec.NewIPSecClient(addr, tlsFiles)
			if err != nil {
				log.Printf("error creating logical bridge: %s\n", err)
			}
			data, err := IPSecEvpnClient.DelSA(ctx, src, dst, spi, proto, ifID)
			if err != nil {
				log.Printf("error creating logical bridge: %s\n", err)
			}
			fmt.Println("AddSAReq marshaled successfully:", data)
		},
	}

	cmd.Flags().StringVar(&src, "src", "", "Source address or hostname")
	cmd.Flags().StringVar(&dst, "dst", "", "Destination address or hostname")
	cmd.Flags().Uint32Var(&spi, "spi", 0, "SPI")
	cmd.Flags().Int32Var(&proto, "proto", 0, "Protocol (ESP/AH)")
	cmd.Flags().Uint32Var(&ifID, "if_id", 0, "Interface ID")

	return cmd
}

// NewEvpnIPSecCommand tests the  inventory
func NewEvpnIPSecCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "evpnipsec",
		Aliases: []string{"g"},
		Short:   "Tests ipsec functionality",
		Args:    cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			err := cmd.Help()
			if err != nil {
				log.Fatalf("[ERROR] %s", err.Error())
			}
		},
	}

	cmd.AddCommand(AddSaCommand())
	cmd.AddCommand(DelSaCommand())
	return cmd
}
