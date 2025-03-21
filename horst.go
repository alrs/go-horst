package horst

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"
)

// TIME, WLAN TYPE, MAC SRC, MAC DST, BSSID, PACKET TYPES, SIGNAL, LENGTH, PHY RATE, FREQUENCY, TSF, ESSID, MODE, CHANNEL, WEP, WPA1, RSN (WPA2), IP SRC, IP DST

const timeLayout = "2006-01-02 15:04:05.000000 -0700"

//  PacketTypes
//	CTRL   WLAN Control frame
//	MGMT   WLAN Management frame
//	DATA   WLAN Data frame
//	BADFCS WLAN frame checksum (FCS) bad
//	BEACON WLAN beacon frame
//	PROBE  WLAN probe request or response
//	ASSOC  WLAN associaction request/response frame
//	AUTH   WLAN authentication frame
//	RTSCTS WLAN RTS or CTS
//	ACK    WLAN ACK or BlockACK
//	NULL   WLAN NULL Data frame
//	QDATA  WLAN QoS Data frame (WME/WMM)
//	ARP    ARP packet
//	IP     IP packet
//	ICMP   IP ICMP packet
//	UDP    IP UDP
//	TCP    IP TCP
//	OLSR   OLSR protocol
//	BATMAN BATMAND Layer3 or BATMAN-ADV Layer 2 frame
//	MESHZ  MeshCruzer protocol

type Packet struct {
	Time        time.Time
	WLANType    string
	MACSRC      net.HardwareAddr
	MACDST      net.HardwareAddr
	BSSID       net.HardwareAddr
	PacketTypes string
	Signal      int
	Length      int
	PhyRate     int
	Frequency   int
	TSF         []byte
	ESSID       string
	Mode        int
	Channel     int
	WEP         bool
	WPA1        bool
	WPA2        bool
	IPSrc       netip.Addr
	IPDst       netip.Addr
}

func ParseHorstFields(record []string) (Packet, error) {
	for i, r := range record {
		// no extra whitespace on first entry
		if i == 0 {
			continue
		}
		// explicitly ditch first character instead of TrimSpace
		record[i] = r[1:]
	}

	l := Packet{}

	t, err := time.Parse(timeLayout, record[0])
	if err != nil {
		return l, fmt.Errorf("parsing time: %v %w", record[0], err)
	}
	l.Time = t

	l.WLANType = record[1]
	s, err := net.ParseMAC(record[2])
	if err != nil {
		return l, fmt.Errorf("parsing WLANType: %v %w", record[1], err)
	}
	l.MACSRC = s

	d, err := net.ParseMAC(record[3])
	if err != nil {
		return l, fmt.Errorf("parsing MACDST: %v %w", record[3], err)
	}
	l.MACDST = d

	b, err := net.ParseMAC(record[4])
	if err != nil {
		return l, fmt.Errorf("parsing BSSID: %v %w", record[4], err)
	}
	l.BSSID = b

	pt := record[5]
	if err != nil {
		return l, fmt.Errorf("parsing PacketTypes: %v %w", record[5], err)
	}
	l.PacketTypes = pt

	sig, err := strconv.Atoi(record[6])
	if err != nil {
		return l, fmt.Errorf("parsing Signal: %v %w", record[6], err)
	}
	l.Signal = sig

	ln, err := strconv.Atoi(record[7])
	if err != nil {
		return l, fmt.Errorf("parsing Length: %v %w", record[7], err)
	}
	l.Length = ln

	pr, err := strconv.Atoi(record[8])
	if err != nil {
		return l, fmt.Errorf("parsing PhyRate: %v %w", record[8], err)
	}
	l.PhyRate = pr

	freq, err := strconv.Atoi(record[9])
	if err != nil {
		return l, fmt.Errorf("parsing Frequency: %v %w", record[9], err)
	}
	l.Frequency = freq

	tsf, err := hex.DecodeString(record[10])
	if err != nil {
		return l, fmt.Errorf("parsing TSF: %v %w", record[10], err)
	}
	l.TSF = tsf

	l.ESSID = record[11]

	mode, err := strconv.Atoi(record[12])
	if err != nil {
		return l, fmt.Errorf("parsing Mode: %v %w", record[12], err)
	}
	l.Mode = mode

	channel, err := strconv.Atoi(record[13])
	if err != nil {
		return l, fmt.Errorf("parsing Channel: %v %w", record[13], err)
	}
	l.Channel = channel

	wep, err := strconv.Atoi(record[14])
	if err != nil {
		return l, fmt.Errorf("parsing WEP: %v %w", record[14], err)
	}
	l.WEP, err = toBool(wep)
	if err != nil {
		return l, fmt.Errorf("toBool WEP: %v %w", wep, err)
	}

	wpa, err := strconv.Atoi(record[15])
	if err != nil {
		return l, fmt.Errorf("parsing WPA: %v %w", record[15], err)
	}
	l.WPA1, err = toBool(wpa)
	if err != nil {
		return l, fmt.Errorf("toBool WPA: %v %w", wpa, err)
	}

	rsn, err := strconv.Atoi(record[16])
	if err != nil {
		return l, fmt.Errorf("parsing WPA2: %v %w", record[16], err)
	}
	l.WPA2, err = toBool(rsn)
	if err != nil {
		return l, fmt.Errorf("toBool WPA2: %v %w", rsn, err)
	}

	ipSrc, err := netip.ParseAddr(record[17])
	if err != nil {
		return l, fmt.Errorf("parsing IPSrc: %v %w", record[17], err)
	}
	l.IPSrc = ipSrc

	ipDst, err := netip.ParseAddr(record[18])
	if err != nil {
		return l, fmt.Errorf("parsing IPDst: %v %w", record[18], err)
	}
	l.IPDst = ipDst
	return l, nil
}

func toBool(i int) (bool, error) {
	if i == 1 {
		return true, nil
	}
	if i == 0 {
		return false, nil
	}
	return false, fmt.Errorf("toBool can only convert \"0\" or \"1\"")
}
