(*
 * Common utilities for pcap digest programs
 *
 * Includes minimal parsing of header fields into a record
 *)

open Printf
open Option

let open_file filename = 
    let fd = Unix.(openfile filename [O_RDONLY] 0) in
    let ba = Bigarray.(array1_of_genarray (Mmap.V1.map_file fd Bigarray.char c_layout false [|-1|])) in
    Cstruct.of_bigarray ba

let read_header filename =
    let buf = open_file filename in
    match Pcap.detect buf with
    | Some h -> h, buf
    | None -> failwith (sprintf "Failed to parse pcap header from %s" filename)

[%%cstruct
type ethernet = {
  dst: uint8_t [@len 6];
  src: uint8_t [@len 6];
  ethertype: uint16_t;
} [@@big_endian]]

[%%cstruct
type ipv4 = {
  hlen_version: uint8_t;
  tos: uint8_t;
  len: uint16_t;
  id: uint16_t;
  off: uint16_t;
  ttl: uint8_t;
  proto: uint8_t;
  csum: uint16_t;
  src: uint32_t;
  dst: uint32_t;
} [@@big_endian]]

[%%cstruct
type tcp = {
  src_port: uint16_t;
  dst_port: uint16_t;
  seqnum: uint32_t;
  acknum: uint32_t;
  offset_flags: uint16_t;
  window: uint16_t;
  checksum: uint16_t;
  urg: uint16_t;
} [@@big_endian]]

[%%cstruct
type udp = {
    src_port: uint16_t;
    dst_port: uint16_t;
    length: uint16_t;
    checksum: uint16_t;
} [@@big_endian]]


let mac_to_string buf =
    let i n = Cstruct.get_uint8 buf n in
    sprintf "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x"
        (i 0) (i 1) (i 2) (i 3) (i 4) (i 5)


let tcp_flags_to_string flags =
    let module TCPFlagsMap = Map.Make(String) in
    let tcp_flags_map =
        TCPFlagsMap.of_seq (List.to_seq [
            ("FIN", 1 lsl 0);
            ("SYN", 1 lsl 1);
            ("RST", 1 lsl 2);
            ("PSH", 1 lsl 3);
            ("ACK", 1 lsl 4);
            ("URG", 1 lsl 5);
            ("ECE", 1 lsl 6);
            ("CWR", 1 lsl 7);
    ]) in
    TCPFlagsMap.(
        fold (fun k _ b -> if b = "" then k else b ^ "|" ^ k) (
            filter (fun _ m -> flags land m = m) tcp_flags_map
    ) ""
)

type ethernet = {
    src : Cstruct.t ;
    dst : Cstruct.t ;
    ethertype : int ;
}

type ipv4 = {
    src : Ipaddr.V4.t ;
    dst : Ipaddr.V4.t ;
    proto : int ;
}

type l4 = {
    sport : int ;
    dport : int ;
    flags : int ;
}

type pkt = {
    ethernet : ethernet ;
    ipv4 : ipv4 ;
    l4 : l4 ;
}

let parse_ethernet eth = {
    src = get_ethernet_src eth ;
    dst = get_ethernet_dst eth ;
    ethertype = get_ethernet_ethertype eth;
}

let parse_ipv4 ip = {
    src = Ipaddr.V4.of_int32 (get_ipv4_src ip);
    dst = Ipaddr.V4.of_int32 (get_ipv4_dst ip);
    proto = get_ipv4_proto ip;
}

let parse_tcp tcp = {
    sport = get_tcp_src_port tcp;
    dport = get_tcp_dst_port tcp;
    flags = (get_tcp_offset_flags tcp) land 0xFF;
}

let parse_udp udp = {
    sport = get_udp_src_port udp;
    dport = get_udp_dst_port udp;
    flags = 0;
}

let parse_pkt p = 
    let ethernet = parse_ethernet p in
    match ethernet.ethertype with
    | 0x0800 ->
        let ipv4 = parse_ipv4 (Cstruct.shift p sizeof_ethernet) in
        (match ipv4.proto with
        | 6 -> let l4 = parse_tcp (Cstruct.shift p (sizeof_ethernet+sizeof_ipv4)) in
            Some {ethernet ; ipv4 ; l4}
        | 17 -> let l4 = parse_udp (Cstruct.shift p (sizeof_ethernet+sizeof_ipv4)) in
            Some {ethernet ; ipv4 ; l4}
        | x -> (printf "unknown ip proto %d " x; None)
        )
    | x -> (printf "unknown ethertype %x " x; None)
