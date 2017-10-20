// +build linux

package netlink

import (
	"encoding/binary"
	"fmt"
	"syscall"

	"github.com/vishvananda/netlink/nl"
)

const (
	FOU_GENL_NAME = "fou"
)

const (
	FOU_CMD_UNSPEC uint8 = iota
	FOU_CMD_ADD
	FOU_CMD_DEL
	FOU_CMD_GET
	FOU_CMD_MAX = FOU_CMD_GET
)

const (
	FOU_ATTR_UNSPEC = iota
	FOU_ATTR_PORT
	FOU_ATTR_AF
	FOU_ATTR_IPPROTO
	FOU_ATTR_TYPE
	FOU_ATTR_REMCSUM_NOPARTIAL
	FOU_ATTR_MAX = FOU_ATTR_REMCSUM_NOPARTIAL
)

const (
	FOU_ENCAP_UNSPEC = iota
	FOU_ENCAP_DIRECT
	FOU_ENCAP_GUE
	FOU_ENCAP_MAX = FOU_ENCAP_GUE
)

var fouFamilyId int

func FouFamilyId() (int, error) {
	if fouFamilyId == 0 {
		fams, err := GenlFamilyList()
		if err != nil {
			return 0, err
		}

		for _, f := range fams {
			if f.Name == FOU_GENL_NAME {
				fouFamilyId = int(f.ID)
				break
			}
		}

		if fouFamilyId == 0 {
			return fouFamilyId, fmt.Errorf("could not find genl family %s", FOU_GENL_NAME)
		}
	}

	return fouFamilyId, nil
}

func FouAdd(f Fou) error {
	return pkgHandle.FouAdd(f)
}

func (h *Handle) FouAdd(f Fou) error {
	fam_id, err := FouFamilyId()
	if err != nil {
		return err
	}

	req := h.newNetlinkRequest(fam_id, syscall.NLM_F_ACK)

	// int to byte for port
	bp := make([]byte, 2)
	binary.BigEndian.PutUint16(bp[0:2], uint16(f.Port))

	attrs := []*nl.RtAttr{
		nl.NewRtAttr(FOU_ATTR_PORT, bp),
		nl.NewRtAttr(FOU_ATTR_TYPE, []byte{uint8(f.EncapType)}),
		nl.NewRtAttr(FOU_ATTR_AF, []byte{uint8(f.Family)}),
		nl.NewRtAttr(FOU_ATTR_IPPROTO, []byte{uint8(f.Protocol)}),
	}
	raw := []byte{FOU_CMD_ADD, 1, 0, 0}
	for _, a := range attrs {
		raw = append(raw, a.Serialize()...)
	}

	req.AddRawData(raw)

	_, err = req.Execute(syscall.NETLINK_GENERIC, 0)
	if err != nil {
		return err
	}

	return nil
}

func FouDel(f Fou) error {
	return pkgHandle.FouDel(f)
}

func (h *Handle) FouDel(f Fou) error {
	fam_id, err := FouFamilyId()
	if err != nil {
		return err
	}

	req := h.newNetlinkRequest(fam_id, syscall.NLM_F_ACK)

	// int to byte for port
	bp := make([]byte, 2)
	binary.BigEndian.PutUint16(bp[0:2], uint16(f.Port))

	attrs := []*nl.RtAttr{
		nl.NewRtAttr(FOU_ATTR_PORT, bp),
		nl.NewRtAttr(FOU_ATTR_AF, []byte{uint8(f.Family)}),
	}
	raw := []byte{FOU_CMD_DEL, 1, 0, 0}
	for _, a := range attrs {
		raw = append(raw, a.Serialize()...)
	}

	req.AddRawData(raw)

	_, err = req.Execute(syscall.NETLINK_GENERIC, 0)
	if err != nil {
		return err
	}

	return nil
}

func FouList(fam int) ([]Fou, error) {
	return pkgHandle.FouList(fam)
}

func (h *Handle) FouList(fam int) ([]Fou, error) {
	fam_id, err := FouFamilyId()
	if err != nil {
		return nil, err
	}

	req := h.newNetlinkRequest(fam_id, syscall.NLM_F_DUMP)

	attrs := []*nl.RtAttr{
		nl.NewRtAttr(FOU_ATTR_AF, []byte{uint8(fam)}),
	}
	raw := []byte{FOU_CMD_GET, 1, 0, 0}
	for _, a := range attrs {
		raw = append(raw, a.Serialize()...)
	}

	req.AddRawData(raw)

	msgs, err := req.Execute(syscall.NETLINK_GENERIC, 0)
	if err != nil {
		return nil, err
	}

	fous := []Fou{}
	for _, m := range msgs {
		if f, err := deserializeFouMsg(m); err != nil {
			return fous, err
		} else {
			fous = append(fous, f)
		}
	}

	return fous, nil
}
