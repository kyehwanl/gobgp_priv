package server

/*
#cgo CFLAGS: -I/opt/project/gobgp_test/tools/go_srx_test
#cgo LDFLAGS: -L/opt/project/gobgp_test/tools/go_srx_test -lSRxBGPSecOpenSSL -lSRxCryptoAPI
#include <stdio.h>
#include "srxcryptoapi.h"

int init(const char* value, int debugLevel, sca_status_t* status);
int sca_SetKeyPath (char* key_path);
*/
import "C"

import (
	_ "bytes"
	_ "encoding/binary"
	_ "encoding/hex"
	"fmt"
	_ "net"
	_ "os"
	_ "unsafe"
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
