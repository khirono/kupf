#ifndef UPF_GTP_H__
#define UPF_GTP_H__

struct gtpv1_hdr {
	__u8    flags;
	__u8    type;
	__be16  length;
	__be32  tid;
} __attribute__((packed));

/* gtpv1_hdr flags */
#define GTPV1_HDR_FLG_NPDU	0x01
#define GTPV1_HDR_FLG_SEQ	0x02
#define GTPV1_HDR_FLG_EXTHDR	0x04
#define GTPV1_HDR_FLG_MASK	0x07

#define GTP_EMARK	254

#endif
