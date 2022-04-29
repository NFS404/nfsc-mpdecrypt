// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"os"
	"strconv"
	"strings"
)

type Keystream struct {
	Stream [256]byte
	A      byte
	B      byte
}

func InitKeystream(key []byte, iters int) *Keystream {
	ks := &Keystream{}
	for i := 0; i < 256; i++ {
		ks.Stream[i] = byte(i)
	}

	for i := 0; i < iters; i++ {
		swap := byte(0)
		for j := 0; j < 256; j += 1 {
			swap += ks.Stream[j] + key[j%len(key)]
			ks.Stream[j], ks.Stream[swap] = ks.Stream[swap], ks.Stream[j]
		}
	}

	return ks
}

func (ks *Keystream) Scramble(iters int) {
	for i := 0; i < iters; i++ {
		ks.A += 1
		ks.B += ks.Stream[ks.A]

		ks.Stream[ks.A], ks.Stream[ks.B] = ks.Stream[ks.B], ks.Stream[ks.A]
	}
}

func (ks *Keystream) Crypt(b []byte) {
	for i := 0; i < len(b); i++ {
		ks.A += 1
		ks.B += ks.Stream[ks.A]

		ks.Stream[ks.A], ks.Stream[ks.B] = ks.Stream[ks.B], ks.Stream[ks.A]

		b[i] = b[i] ^ ks.Stream[ks.Stream[ks.A]+ks.Stream[ks.B]]
	}
}

func fatal(str string, args ...interface{}) {
	_, _ = fmt.Fprintf(os.Stderr, str, args...)
	os.Exit(1)
}

func main() {
	if len(os.Args) < 5 {
		fatal("Usage: %s in.pcapng out.pcapng ekey port\n", os.Args[0])
	}
	f, err := os.Open(os.Args[1])
	if err != nil {
		fatal("Failed to open input file: %v\n", err)
	}
	rd, err := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
	if err != nil {
		fatal("Failed to create pcap reader: %v\n", err)
	}

	fout, err := os.Create(os.Args[2])
	if err != nil {
		fatal("Failed to create output file: %v\n", err)
	}
	wr, err := pcapgo.NewNgWriter(fout, layers.LinkTypeEthernet)
	if err != nil {
		fatal("Failed to create pcap writer: %v\n", err)
	}
	defer wr.Flush()
	defer fout.Close()

	ekey := os.Args[3]
	keyBytes := []byte(ekey)[:16]
	if strings.HasPrefix(os.Args[4], "int:") {
		os.Args[4] = strings.TrimPrefix(os.Args[4], "int:")
		for i := 0; i < 16; i++ {
			keyBytes[i] = ^keyBytes[i]
		}
	}
	dstPort, err := strconv.Atoi(os.Args[4])
	if err != nil {
		fatal("Failed to parse destination port: %v\n", err)
	}
	sendKS := InitKeystream(keyBytes, 1)
	recvKS := InitKeystream(keyBytes, 1)

	for {
		data, srcCi, err := rd.ReadPacketData()
		if err != nil {
			return
		}
		pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
		if udpLayer := pkt.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp := udpLayer.(*layers.UDP)
			if udp.DstPort != layers.UDPPort(dstPort) && udp.SrcPort != layers.UDPPort(dstPort) {
				continue
			}
			fmt.Printf("udp %d -> %d\n", udp.SrcPort, udp.DstPort)

			var keystream *Keystream
			if udp.DstPort == layers.UDPPort(dstPort) {
				keystream = sendKS
			} else {
				keystream = recvKS
			}

			ksPos := byte(binary.BigEndian.Uint16(udp.Payload[:2]) * 4)
			if ksPos > keystream.A {
				keystream.Scramble(int(ksPos - keystream.A))
			}
			payload := udp.Payload[2:]
			keystream.Crypt(payload)

			layers := make([]gopacket.SerializableLayer, len(pkt.Layers()))
			for i := 0; i < len(layers)-1; i++ {
				layers[i] = pkt.Layers()[i].(gopacket.SerializableLayer)
			}
			layers[len(layers)-1] = gopacket.Payload(payload)
			buf := gopacket.NewSerializeBuffer()
			if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, layers...); err != nil {
				panic(err)
			}
			ci := gopacket.CaptureInfo{
				Timestamp:     srcCi.Timestamp,
				CaptureLength: len(buf.Bytes()),
				Length:        len(buf.Bytes()),
			}
			if err := wr.WritePacket(ci, buf.Bytes()); err != nil {
				panic(err)
			}
		}
	}
}
