package server

/*
#cgo CFLAGS: -I/opt/project/gobgp_test/tools/go_srx_test
#cgo LDFLAGS: -L/opt/project/gobgp_test/tools/go_srx_test -lSRxBGPSecOpenSSL -lSRxCryptoAPI
#include <stdio.h>
#include <stdlib.h>
#include "srxcryptoapi.h"

void PrintSCA_Prefix2(SCA_Prefix p){
	printf("From C prefix\n  afi:\t%d\n  safi:\t%d\n  length:\t%d\n  addr:\t%x\n\n",
		p.afi, p.safi, p.length, p.addr.ip);
}
int init(const char* value, int debugLevel, sca_status_t* status);
int sca_SetKeyPath (char* key_path);
int validate(SCA_BGPSecValidationData* data);
void printHex(int len, unsigned char* buff);
*/
import "C"

import (
	"bytes"
	"encoding/binary"
	_ "encoding/hex"
	"fmt"
	log "github.com/Sirupsen/logrus"
	_ "github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet/bgp"
	_ "github.com/osrg/gobgp/table"
	"net"
	_ "os"
	"unsafe"
)

type scaStatus uint32

type bgpsecManager struct {
	AS uint32
}

func (bm *bgpsecManager) BgpsecInit(as uint32) ([]byte, error) {

	// --------- call sca_SetKeyPath -----------------------
	fmt.Printf("+ setKey path call testing...\n\n")
	//sca_SetKeyPath needed in libSRxCryptoAPI.so

	keyPath := C.CString("/opt/project/srx_test1/keys/")
	keyRet := C.sca_SetKeyPath(keyPath)
	fmt.Println("sca_SetKeyPath() return:", keyRet)
	if keyRet != 1 {
		fmt.Errorf("setKey failed")
	}

	// --------- call Init() function ---------------------
	fmt.Printf("+ Init call testing...\n\n")

	//str := C.CString("PRIV:/opt/project/srx_test1/keys/priv-ski-list.txt")
	str := C.CString("PUB:/opt/project/srx_test1/keys/ski-list.txt;PRIV:/opt/project/srx_test1/keys/priv-ski-list.txt")
	fmt.Printf("+ str: %s\n", C.GoString(str))

	var stat *scaStatus
	initRet := C.init(str, C.int(7), (*C.uint)(stat))
	fmt.Println("Init() return:", initRet)
	if initRet != 1 {
		fmt.Errorf("init failed")
	}

	return nil, nil
}

func (bm *bgpsecManager) validate(e *FsmMsg) {
	m := e.MsgData.(*bgp.BGPMessage)
	update := m.Body.(*bgp.BGPUpdate)
	log.WithFields(log.Fields{"Topic": "bgpsec"}).Infof("Validate server operated ")

	var nlri_processed bool
	var prefix_addr net.IP
	var prefix_len uint8
	var nlri_afi uint16
	var nlri_safi uint8

	// find the position of bgpsec attribute
	//
	data := e.payload
	data = data[bgp.BGP_HEADER_LENGTH:]
	if update.WithdrawnRoutesLen > 0 {
		data = data[2+update.WithdrawnRoutesLen:]
	} else {
		data = data[2:]
	}

	data = data[2:]
	for pathlen := update.TotalPathAttributeLen; pathlen > 0; {
		p, _ := bgp.GetPathAttribute(data)
		p.DecodeFromBytes(data)

		pathlen -= uint16(p.Len())

		if bgp.BGPAttrType(data[1]) != bgp.BGP_ATTR_TYPE_BGPSEC {
			data = data[p.Len():]
		} else {
			break
		}
	}

	//
	// find nlri attribute first and extract prefix info for bgpsec validation
	//
	for _, path := range e.PathList {

		// find MP NLRI attribute first
		for _, p := range path.GetPathAttrs() {
			typ := uint(p.GetType())
			if typ == uint(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI) {
				fmt.Printf("received MP NLRI: %#v\n", path)
				prefix_addr = p.(*bgp.PathAttributeMpReachNLRI).Value[0].(*bgp.IPAddrPrefix).Prefix
				prefix_len = p.(*bgp.PathAttributeMpReachNLRI).Value[0].(*bgp.IPAddrPrefix).Length
				nlri_afi = p.(*bgp.PathAttributeMpReachNLRI).AFI
				nlri_safi = p.(*bgp.PathAttributeMpReachNLRI).SAFI

				fmt.Println("prefix:", prefix_addr, prefix_len, nlri_afi, nlri_safi)
				nlri_processed = true
				fmt.Printf("received MP NLRI: %#v\n", nlri_processed)
			}
		}

		// find the BGPSec atttribute
		for _, p := range path.GetPathAttrs() {
			typ := uint(p.GetType())
			if typ == uint(bgp.BGP_ATTR_TYPE_BGPSEC) && nlri_processed {
				fmt.Printf("+++ bgpsec validation start \n")

				var myas uint32 = bm.AS
				big2 := make([]byte, 4, 4)
				for i := 0; i < 4; i++ {
					u8 := *(*uint8)(unsafe.Pointer(uintptr(unsafe.Pointer(&myas)) + uintptr(i)))
					big2 = append(big2, u8)
				}

				valData := C.SCA_BGPSecValidationData{
					myAS:             C.uint(binary.BigEndian.Uint32(big2[4:8])),
					status:           C.sca_status_t(0),
					bgpsec_path_attr: nil,
					nlri:             nil,
					hashMessage:      [2](*C.SCA_HashMessage){},
				}

				// signature  buffer handling
				//
				bs_path_attr_length := 0x6c // 0x68 + 4
				pa := C.malloc(C.ulong(bs_path_attr_length))
				defer C.free(pa)

				buf := &bytes.Buffer{}
				bs_path_attr := data
				binary.Write(buf, binary.BigEndian, bs_path_attr)
				bl := buf.Len()
				o := (*[1 << 20]C.uchar)(pa)

				for i := 0; i < bl; i++ {
					b, _ := buf.ReadByte()
					o[i] = C.uchar(b)
				}
				valData.bgpsec_path_attr = (*C.uchar)(pa)

				// prefix handling
				//
				prefix2 := (*C.SCA_Prefix)(C.malloc(C.sizeof_SCA_Prefix))
				defer C.free(unsafe.Pointer(prefix2))
				px := &bgp.Go_SCA_Prefix{
					Afi:    nlri_afi,
					Safi:   nlri_safi,
					Length: prefix_len,
					Addr:   [16]byte{},
				}

				pxip := prefix_addr
				copy(px.Addr[:], pxip)
				px.Pack(unsafe.Pointer(prefix2))
				C.PrintSCA_Prefix2(*prefix2)
				fmt.Printf("prefix2 : %#v\n", prefix2)

				valData.nlri = prefix2
				fmt.Printf(" valData : %#v\n", valData)
				fmt.Printf(" valData.bgpsec_path_attr : %#v\n", valData.bgpsec_path_attr)
				C.printHex(C.int(bs_path_attr_length), valData.bgpsec_path_attr)
				fmt.Printf(" valData.nlri : %#v\n", *valData.nlri)

				// call validate
				ret := C.validate(&valData)

				fmt.Println("return: value:", ret, " and status: ", valData.status)
				if ret == 1 {
					fmt.Println(" +++ Validation function SUCCESS ...")

				} else if ret == 0 {
					fmt.Println(" Validation function Failed...")
					switch valData.status {
					case 1:
						fmt.Println("Status Error: signature error")
					case 2:
						fmt.Println("Status Error: Key not found")
					case 0x10000:
						fmt.Println("Status Error: no data")
					case 0x20000:
						fmt.Println("Status Error: no prefix")
					case 0x40000:
						fmt.Println("Status Error: Invalid key")
					case 0x10000000:
						fmt.Println("Status Error: USER1")
					case 0x20000000:
						fmt.Println("Status Error: USER2")
					}
				}

			} // end of if - bgpsec validation process

		}

	} // end of if - path list
}

func (bm *bgpsecManager) SetAS(as uint32) error {
	if bm.AS != 0 {
		return fmt.Errorf("AS was already configured")
	}
	bm.AS = as
	return nil
}

func NewBgpsecManager(as uint32) (*bgpsecManager, error) {
	m := &bgpsecManager{
		AS: as,
	}
	m.BgpsecInit(as)
	return m, nil
}

/*
typedef u_int32_t sca_status_t;

typedef struct
{
  u_int8_t* signaturePtr;
  u_int8_t* hashMessagePtr;
  u_int16_t hashMessageLength;
} SCA_HashMessagePtr;

typedef struct
{
  bool      ownedByAPI;
  u_int32_t bufferSize;
  u_int8_t* buffer;
  u_int16_t segmentCount;
  SCA_HashMessagePtr** hashMessageValPtr;
} SCA_HashMessage;


typedef struct
{
  bool      ownedByAPI;
  u_int8_t  algoID;
  u_int8_t  ski[SKI_LENGTH];
  u_int16_t sigLen;
  u_int8_t* sigBuff;
} SCA_Signature;


typedef struct {
  u_int8_t  pCount;
  u_int8_t  flags;
  u_int32_t asn;
} __attribute__((packed)) SCA_BGPSEC_SecurePathSegment;


typedef struct
{
  u_int16_t afi;
  u_int8_t  safi;
  u_int8_t  length;
  union
  {
    struct in_addr  ipV4;
    struct in6_addr ipV6;
    u_int8_t ip[16];
  } addr;
} __attribute__((packed)) SCA_Prefix;


typedef struct
{
  __attribute__((deprecated))u_int32_t peerAS;
  __attribute__((deprecated))SCA_BGPSEC_SecurePathSegment* myHost;
  __attribute__((deprecated))SCA_Prefix* nlri;

  u_int32_t myASN;
  u_int8_t* ski;
  u_int8_t algorithmID;
  sca_status_t status;
  SCA_HashMessage*  hashMessage;

  SCA_Signature* signature;
} SCA_BGPSecSignData;
*/
