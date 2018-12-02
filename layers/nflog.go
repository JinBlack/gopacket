// Copyright 2012 Google, Inc. All rights reserved.
// Copyright 2009-2011 Andreas Krennmair. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/google/gopacket"
)

type NFLogTLV struct {
	Lenght uint16
	Type   NFLogTLVType
	Value  []byte
}

// NFLog is the layer for NFLog.
type NFLog struct {
	BaseLayer
	NFLogFamilyType NFLogFamilyType
	EthernetType    EthernetType

	Version    uint8
	ResourceID uint16
	TLVs       []NFLogTLV
}

// LayerType returns LayerTypeEthernet
func (e *NFLog) LayerType() gopacket.LayerType { return LayerTypeNFLog }

// func (e *NFLog) LinkFlow() gopacket.Flow {
// 	return gopacket.NewFlow(EndpointMAC, e.SrcMAC, e.DstMAC)
// }

func (nfl *NFLog) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 4 {
		return errors.New("NFLog packet too small")
	}
	nfl.NFLogFamilyType = NFLogFamilyType(data[0])
	nfl.Version = uint8(data[1])
	nfl.ResourceID = binary.LittleEndian.Uint16(data[2:])

	pIndex := 4
	// You need al least 4 bytes to decode a TLV
	for pIndex < len(data)-4 {
		newTLV := NFLogTLV{}
		newTLV.Lenght = binary.LittleEndian.Uint16(data[pIndex:])

		newTLV.Type = NFLogTLVType(binary.LittleEndian.Uint16(data[pIndex+2:]))
		if int(newTLV.Lenght)+pIndex > len(data) {
			return fmt.Errorf("Invalid Lenght of TLV: %d", newTLV.Lenght)
		}
		newTLV.Value = data[pIndex+4 : pIndex+int(newTLV.Lenght)]
		// TODO This is weird need to check the standard.
		if newTLV.Lenght < 8 && newTLV.Lenght != 4 {
			pIndex += 8
		} else {
			pIndex += int(newTLV.Lenght)
		}
		if newTLV.Type == NFULA_PACKET_HDR {
			nfl.EthernetType = EthernetType(binary.BigEndian.Uint16(newTLV.Value))
		}
		if newTLV.Type == NFULA_PAYLOAD {
			nfl.Payload = newTLV.Value
		}

	}

	return nil
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (eth *NFLog) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// if len(eth.DstMAC) != 6 {
	// 	return fmt.Errorf("invalid dst MAC: %v", eth.DstMAC)
	// }
	// if len(eth.SrcMAC) != 6 {
	// 	return fmt.Errorf("invalid src MAC: %v", eth.SrcMAC)
	// }
	// payload := b.Bytes()
	// bytes, err := b.PrependBytes(14)
	// if err != nil {
	// 	return err
	// }
	// copy(bytes, eth.DstMAC)
	// copy(bytes[6:], eth.SrcMAC)
	// if eth.Length != 0 || eth.EthernetType == EthernetTypeLLC {
	// 	if opts.FixLengths {
	// 		eth.Length = uint16(len(payload))
	// 	}
	// 	if eth.EthernetType != EthernetTypeLLC {
	// 		return fmt.Errorf("ethernet type %v not compatible with length value %v", eth.EthernetType, eth.Length)
	// 	} else if eth.Length > 0x0600 {
	// 		return fmt.Errorf("invalid ethernet length %v", eth.Length)
	// 	}
	// 	binary.BigEndian.PutUint16(bytes[12:], eth.Length)
	// } else {
	// 	binary.BigEndian.PutUint16(bytes[12:], uint16(eth.EthernetType))
	// }
	// length := len(b.Bytes())
	// if length < 60 {
	// 	// Pad out to 60 bytes.
	// 	padding, err := b.AppendBytes(60 - length)
	// 	if err != nil {
	// 		return err
	// 	}
	// 	copy(padding, lotsOfZeros[:])
	// }
	return nil
}

func (eth *NFLog) CanDecode() gopacket.LayerClass {
	return LayerTypeNFLog
}

func (eth *NFLog) NextLayerType() gopacket.LayerType {
	return eth.NFLogFamilyType.LayerType()
}

func decodeNFLog(data []byte, p gopacket.PacketBuilder) error {
	nfl := &NFLog{}
	err := nfl.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(nfl)
	// p.SetLinkLayer(eth)
	return p.NextDecoder(nfl.EthernetType)
}
