// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// This file tests some of the functionality provided in the ip4.go

package layers

import (
	"encoding/hex"
	"testing"

	"github.com/google/gopacket"
)

//Test NFLog decoding
func TestNFLogDecoding(t *testing.T) {
	var nfl NFLog // reuse ip4 to test reset
	for _, test := range []struct {
		packet  string
		options []IPv4Option
		padding []byte
	}{
		{
			packet: "02000001080001000800020005000a0000000000080004000000003d080005000000008f06000f00fffe000006001100000000000400100014000300000000005be6ecff000000000009c8783f0009004500003ba10140003e06c52b0a3c38020a508a0222b8cef0f7905610e6f20635801805ac77ba00000101080aedea5c1950d1a295810566616c736500",
			options: []IPv4Option{
				{
					OptionType:   130,
					OptionData:   []byte{0, 0, 0, 0, 0, 0, 0, 0, 0},
					OptionLength: 11,
				},
				{
					OptionType:   0,
					OptionLength: 1,
				},
			},
		},
	} {
		b, err := hex.DecodeString(test.packet)
		if err != nil {
			t.Fatalf("Failed to Decode header: %v", err)
		}
		err = nfl.DecodeFromBytes(b, gopacket.NilDecodeFeedback)
		if err != nil {
			t.Fatal("Unexpected error during decoding:", err)
		}
		// if !reflect.DeepEqual(ip4.Options, test.options) {
		// 	t.Fatalf("Options mismatch.\nGot:\n%#v\nExpected:\n%#v\n", ip4.Options, test.options)
		// }
		// if !bytes.Equal(ip4.Padding, test.padding) {
		// 	t.Fatalf("Padding mismatch.\nGot:\n%#v\nExpected:\n%#v\n", ip4.Padding, test.padding)
		// }
	}
}
