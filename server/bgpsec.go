package server

/*
#cgo CFLAGS: -I/opt/project/gobgp_test/tools/go_srx_test
#cgo LDFLAGS: -L/opt/project/gobgp_test/tools/go_srx_test -lSRxBGPSecOpenSSL -lSRxCryptoAPI
#include <stdio.h>
#include <stdlib.h>
#include "srxcryptoapi.h"

void PrintPacked(SCA_BGPSEC_SecurePathSegment p){
     printf("From C path segment \n  pCount:\t%d\n  flags:\t%x\n  asn:\t%d\n\n", p.pCount, p.flags, p.asn);
}
void PrintSCA_Prefix(SCA_Prefix p){
	printf("From C prefix\n  afi:\t%d\n  safi:\t%d\n  length:\t%d\n  addr:\t%x\n\n",
		p.afi, p.safi, p.length, p.addr.ip);
}

int init(const char* value, int debugLevel, sca_status_t* status);
int sca_SetKeyPath (char* key_path);
int _sign(SCA_BGPSecSignData* signData );
int validate(SCA_BGPSecValidationData* data);
int sca_generateHashMessage(SCA_BGPSecValidationData* data, u_int8_t algoID, sca_status_t* status);
void printHex(int len, unsigned char* buff);
*/
import "C"

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet/bgp"
	//_ "github.com/osrg/gobgp/table"
	"net"
	_ "os"
	"unsafe"
)

type Go_SCA_Prefix struct {
	Afi    uint16
	Safi   uint8
	Length uint8
	Addr   [16]uint8
}

func (g *Go_SCA_Prefix) Pack(out unsafe.Pointer) {

	buf := &bytes.Buffer{}
	binary.Write(buf, binary.BigEndian, g)
	l := buf.Len()
	o := (*[1 << 20]C.uchar)(out)

	for i := 0; i < l; i++ {
		b, _ := buf.ReadByte()
		o[i] = C.uchar(b)
	}
}

type Go_SCA_BGPSEC_SecurePathSegment struct {
	pCount uint8
	flags  uint8
	asn    uint32
}

func (g *Go_SCA_BGPSEC_SecurePathSegment) Pack(out unsafe.Pointer) {

	buf := &bytes.Buffer{}
	/*
	   binary.Write(buf, binary.LittleEndian, g.pCount)
	   binary.Write(buf, binary.LittleEndian, g.flags)
	   binary.Write(buf, binary.LittleEndian, g.asn)
	*/
	//binary.Write(buf, binary.LittleEndian, g)
	binary.Write(buf, binary.BigEndian, g)

	// get the length of memory
	l := buf.Len()

	//Cast the point to byte slie to allow for direct memory manipulation
	o := (*[1 << 20]C.uchar)(out)

	//Write to memory
	for i := 0; i < l; i++ {
		b, _ := buf.ReadByte()
		o[i] = C.uchar(b)
	}
}

type BgpsecCrypto struct {
	Peer_as  uint32
	Local_as uint32
	SKI_str  string
	PxAddr   net.IP
	PxLen    uint8
	Afi      uint16
	Safi     uint8
}

func (bc *BgpsecCrypto) GenerateSignature(sp []bgp.SecurePathInterface, bm *bgpsecManager) ([]byte, uint16) {

	//
	//  call _sign() function
	//
	fmt.Printf("+ bgpsec sign data testing...\n\n")
	//sp := bpa.(*bgp.PathAttributeBgpsec).SecurePathValue.(*bgp.SecurePath)
	sp_value := sp[0].(*bgp.SecurePath).SecurePathSegments[0]
	fmt.Println("+++ secure path value:", sp_value)

	// ------ prefix handling ---------------
	ga := &Go_SCA_Prefix{
		Afi:    bc.Afi,
		Safi:   bc.Safi,
		Length: bc.PxLen,
		Addr:   [16]byte{},
	}
	prefix := (*C.SCA_Prefix)(C.malloc(C.sizeof_SCA_Prefix))
	defer C.free(unsafe.Pointer(prefix))
	//ad := C.SCA_Prefix{}
	//ipstr := "100.1.1.0"
	//IPAddress := net.ParseIP(ipstr)
	//copy(ga.addr[:], IPAddress[12:16])
	copy(ga.Addr[:], bc.PxAddr)

	//fmt.Printf("ipaddress: %#v\n", IPAddress )
	//fmt.Println("4-byte rep: ", IPAddress.To4())
	//fmt.Println("ip: ", binary.BigEndian.Uint32(IPAddress[12:16]))

	//ga.Pack(unsafe.Pointer(&ad))
	//C.PrintSCA_Prefix(ad)

	ga.Pack(unsafe.Pointer(prefix))
	C.PrintSCA_Prefix(*prefix)

	fmt.Printf("bc.Pxaddr: %#v, ga.addr: %#v, prefix.addr:%#v\n", bc.PxAddr, ga.Addr, prefix)

	//os.Exit(3)

	// ------- Library call: printHex function test ----------
	b := [...]byte{0x11, 0x22, 0x33}
	var cb [10]C.uchar
	cb[0] = C.uchar(b[0])
	cb[1] = C.uchar(b[1])
	cb[2] = C.uchar(b[2])
	//cb := C.uchar(b)
	C.printHex(C.int(10), &cb[0])

	// ------ secure Path segment generation ---------------
	u := &Go_SCA_BGPSEC_SecurePathSegment{
		pCount: sp_value.PCount,
		flags:  sp_value.Flags,
		asn:    bc.Peer_as,
	}
	sps := (*C.SCA_BGPSEC_SecurePathSegment)(C.malloc(C.sizeof_SCA_BGPSEC_SecurePathSegment))
	defer C.free(unsafe.Pointer(sps))
	u.Pack(unsafe.Pointer(sps))

	//fmt.Printf("data:%#v\n\n", *sps)
	//fmt.Printf("data:%+v\n\n", *sps)
	C.PrintPacked(*sps)

	// ------ ski handling ---------------
	bs, _ := hex.DecodeString(bc.SKI_str)
	fmt.Printf("type of bs: %T\n", bs)
	fmt.Printf("string test: %02X \n", bs)

	cbuf := (*[20]C.uchar)(C.malloc(20))
	defer C.free(unsafe.Pointer(cbuf))
	cstr := (*[20]C.uchar)(unsafe.Pointer(&bs[0]))
	for i := 0; i < 20; i++ {
		cbuf[i] = cstr[i]
	}

	// ------ hash message handling  ---------------
	hashData := C.SCA_HashMessage{
		ownedByAPI:        true,
		bufferSize:        100,
		buffer:            nil,
		segmentCount:      1,
		hashMessageValPtr: nil,
	}
	hash := C.malloc(C.sizeof_SCA_HashMessage)
	defer C.free(unsafe.Pointer(hash))
	h1 := (*[1000]C.uchar)(unsafe.Pointer(&hashData))
	h2 := (*[1000]C.uchar)(hash)
	for i := 0; i < C.sizeof_SCA_HashMessage; i++ {
		h2[i] = h1[i]
	}
	//bgpsecData.hashMessage = (*C.SCA_HashMessage)(hash)
	//bgpsecData.hashMessage = nil
	if bm.bgpsec_path_attr != nil {
		fmt.Println("path attr:", bm.bgpsec_path_attr)
	}

	var peeras uint32 = bc.Local_as
	big := make([]byte, 4, 4)
	for i := 0; i < 4; i++ {
		u8 := *(*uint8)(unsafe.Pointer(uintptr(unsafe.Pointer(&peeras)) + uintptr(i)))
		big = append(big, u8)
	}

	fmt.Printf("++ peerAS :%#v\n", big)
	fmt.Printf("++ peerAS BigEndian :%#v\n", binary.BigEndian.Uint32(big[4:8]))

	bgpsecData := C.SCA_BGPSecSignData{
		peerAS:      C.uint(binary.BigEndian.Uint32(big[4:8])),
		myHost:      sps,
		nlri:        prefix,
		myASN:       C.uint(bc.Peer_as),
		ski:         (*C.uchar)(&cbuf[0]),
		algorithmID: 1,
		status:      C.sca_status_t(0),
		hashMessage: nil,
		signature:   nil,
	}

	if bm.bgpsec_path_attr != nil {
		fmt.Println("path attr:", bm.bgpsec_path_attr)
		fmt.Println("val data:", bm.bgpsecValData)

		pa := C.malloc(C.ulong(bm.bgpsec_path_attr_length))
		buf := &bytes.Buffer{}
		bs_path_attr := bm.bgpsec_path_attr
		binary.Write(buf, binary.BigEndian, bs_path_attr)
		bl := buf.Len()
		o := (*[1 << 20]C.uchar)(pa)

		for i := 0; i < bl; i++ {
			b, _ := buf.ReadByte()
			o[i] = C.uchar(b)
		}
		bm.bgpsecValData.bgpsec_path_attr = (*C.uchar)(pa)

		C.sca_generateHashMessage(&bm.bgpsecValData, C.SCA_ECDSA_ALGORITHM,
			&bm.bgpsecValData.status)
		bgpsecData.hashMessage = bm.bgpsecValData.hashMessage[0]
	}

	retVal := C._sign(&bgpsecData)

	fmt.Println("return: value:", retVal, " and status: ", bgpsecData.status)
	if retVal == 1 {
		fmt.Println(" _sign function SUCCESS ...")

		if bgpsecData.signature != nil {
			fmt.Printf("signature: %#v\n", bgpsecData.signature)

			ret_array := func(sig_data *C.SCA_Signature) []uint8 {
				buf := make([]uint8, 0, uint(sig_data.sigLen))
				for i := 0; i < int(sig_data.sigLen); i++ {
					u8 := *(*uint8)(unsafe.Pointer(uintptr(unsafe.Pointer(sig_data.sigBuff)) + uintptr(i)))
					buf = append(buf, u8)
				}
				return buf
			}(bgpsecData.signature)

			fmt.Println("ret:", ret_array)

			return []byte(ret_array), uint16(bgpsecData.signature.sigLen)
		}

	} else if retVal == 0 {
		fmt.Println(" _sign function Failed ...")
		switch bgpsecData.status {
		case 1:
			fmt.Println("signature error")
		case 2:
			fmt.Println("Key not found")
		case 0x10000:
			fmt.Println("no data")
		case 0x20000:
			fmt.Println("no prefix")
		case 0x40000:
			fmt.Println("Invalid key")
		}
	}
	return nil, 0
}

type scaStatus uint32

type bgpsecManager struct {
	AS                      uint32
	KeyPath                 string
	bgpsec_path_attr        []byte
	bgpsec_path_attr_length uint16
	bgpsecValData           C.SCA_BGPSecValidationData
}

func (bm *bgpsecManager) BgpsecInit(key string) ([]byte, error) {

	// --------- call sca_SetKeyPath -----------------------
	fmt.Printf("+ setKey path call testing...\n\n")
	//sca_SetKeyPath needed in libSRxCryptoAPI.so

	keyPath := C.CString(key)
	keyRet := C.sca_SetKeyPath(keyPath)
	fmt.Println("sca_SetKeyPath() return:", keyRet)
	if keyRet != 1 {
		fmt.Errorf("setKey failed")
	}

	// --------- call Init() function ---------------------
	fmt.Printf("+ Init call testing...\n\n")

	str := C.CString("PUB:" + key + "/ski-list.txt;PRIV:" + key + "/priv-ski-list.txt")
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

				var bs_path_attr_length uint16
				Flags := bgp.BGPAttrFlag(data[0])
				if Flags&bgp.BGP_ATTR_FLAG_EXTENDED_LENGTH != 0 {
					bs_path_attr_length = binary.BigEndian.Uint16(data[2:4])
				} else {

					bs_path_attr_length = uint16(data[2])
				}

				bs_path_attr_length = bs_path_attr_length + 4 // flag(1) + length(1) + its own length octet (2)
				data = data[:bs_path_attr_length]
				// signature  buffer handling
				//
				pa := C.malloc(C.ulong(bs_path_attr_length))
				defer C.free(pa)

				buf := &bytes.Buffer{}
				bs_path_attr := data

				bm.bgpsec_path_attr = data
				bm.bgpsec_path_attr_length = bs_path_attr_length

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
				//defer C.free(unsafe.Pointer(prefix2))
				px := &Go_SCA_Prefix{
					Afi:    nlri_afi,
					Safi:   nlri_safi,
					Length: prefix_len,
					Addr:   [16]byte{},
				}

				pxip := prefix_addr
				copy(px.Addr[:], pxip)
				px.Pack(unsafe.Pointer(prefix2))
				C.PrintSCA_Prefix(*prefix2)
				fmt.Printf("prefix2 : %#v\n", prefix2)

				valData.nlri = prefix2
				fmt.Printf(" valData : %#v\n", valData)
				fmt.Printf(" valData.bgpsec_path_attr : %#v\n", valData.bgpsec_path_attr)
				C.printHex(C.int(bs_path_attr_length), valData.bgpsec_path_attr)
				fmt.Printf(" valData.nlri : %#v\n", *valData.nlri)

				bm.bgpsecValData = valData
				// call validate
				ret := C.validate(&valData)

				fmt.Println("return: value:", ret, " and status: ", valData.status)

				result := config.RPKI_VALIDATION_RESULT_TYPE_NONE
				switch ret {
				case 1:
					fmt.Println(" +++ Validation function SUCCESS ...")
					result = config.RPKI_VALIDATION_RESULT_TYPE_VALID
				case 0:
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
					result = config.RPKI_VALIDATION_RESULT_TYPE_INVALID
				default:
					result = config.RPKI_VALIDATION_RESULT_TYPE_NOT_FOUND
				}
				path.SetBgpsecValidation(result)

			} // end of if - bgpsec validation process
		} // end of if, get path attr
	} // end of if - path list
}

func (bm *bgpsecManager) SetAS(as uint32) error {
	if bm.AS != 0 {
		return fmt.Errorf("AS was already configured")
	}
	bm.AS = as
	return nil
}

func (bm *bgpsecManager) SetKeyPath(keyPath string) error {
	log.WithFields(log.Fields{"Topic": "bgpsec"}).Infof("key path set: %s", keyPath)
	bm.KeyPath = keyPath
	return nil
}

func NewBgpsecManager(as uint32) (*bgpsecManager, error) {
	m := &bgpsecManager{
		AS:                      as,
		bgpsec_path_attr:        make([]byte, 0),
		bgpsec_path_attr_length: 0,
		bgpsecValData:           C.SCA_BGPSecValidationData{},
	}
	//m.BgpsecInit(as)
	return m, nil
}
