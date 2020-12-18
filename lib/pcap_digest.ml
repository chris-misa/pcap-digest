(*
 * Common utilities for pcap digest programs
 *
 * Includes minimal parsing of header fields into a record
 *)

open Printf
open Option

(* Read a file and return the Pcap.HDR header reader module and Cstruct.t with file contents *)
(* val read_header : string -> ((module Pcap.HDR) * Cstruct.t) *)

(* Convert 6-byte mac address to human-readable string *)
(* val mac_to_string : Cstruct.t -> string *)

(* Convert tcp flags byte to human-readable string *)
(* val tcp_flags_to_string : int -> string *)

(* Nested record type for packet headers *)
type ethernet = {
    src : Cstruct.t ;
    dst : Cstruct.t ;
    ethertype : int ;
}
type ipv4 = {
    hlen : int ;
    proto : int ;
    src : Ipaddr.V4.t ;
    dst : Ipaddr.V4.t ;
}
type l4 = {
    sport : int ;
    dport : int ;
    flags : int ;
}
type pkt = {
    time : float ;
    ethernet : ethernet option ;
    ipv4 : ipv4 ;
    l4 : l4 ;
}

(* Parse packet into nested record *)
(* val parse_pkt : Cstruct.t -> pkt *)

(* Module signature for operations *)
module type PcapOperation =
sig
    (* Intermediate type produced in fold *)
    type t

    (* Return the initial value *)
    val init : unit -> t 

    (* Process one packet *)
    val proc : pkt -> t -> t

    (* Print summary after fold completes *)
    val final : t -> unit
end

module IPv4Set = Set.Make(Ipaddr.V4)

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


let parse_ethernet eth =
{
    src = get_ethernet_src eth ;
    dst = get_ethernet_dst eth ;
    ethertype = get_ethernet_ethertype eth;
}

let parse_ipv4 ip = 
{
    hlen = (get_ipv4_hlen_version ip) land 0xF;
    proto = get_ipv4_proto ip;
    src = Ipaddr.V4.of_int32 (get_ipv4_src ip);
    dst = Ipaddr.V4.of_int32 (get_ipv4_dst ip);
}

let parse_tcp tcp = 
{
    sport = get_tcp_src_port tcp;
    dport = get_tcp_dst_port tcp;
    flags = (get_tcp_offset_flags tcp) land 0xFF;
}

let parse_udp udp =
{
    sport = get_udp_src_port udp;
    dport = get_udp_dst_port udp;
    flags = 0;
}


let get_ip_version eth offset = 
    ((Cstruct.get_uint8 eth offset) land 0xF0) lsr 4


let parse_pkt network h hdr p = 
    let module H = (val h: Pcap.HDR) in
    let time = (Int32.to_float (H.get_pcap_packet_ts_sec hdr)) +. (Int32.to_float (H.get_pcap_packet_ts_usec hdr)) /. 1000000. in
    let ethernet, offset = (
        match network with
        | 1 -> (Some (parse_ethernet p), sizeof_ethernet)
        | 101 -> (None, 0)
        | x -> failwith (sprintf "Unknown pcap network value: %d" x)
    ) in
    try
        let ipv4, offset = (
            match get_ip_version p offset with
            | 4 -> let ipv4 = parse_ipv4 (Cstruct.shift p offset) in (ipv4, offset + (ipv4.hlen * 4))
            | _ -> raise (Invalid_argument "")
        ) in
        let l4 = (
            match ipv4.proto with
            | 6 -> parse_tcp (Cstruct.shift p offset)
            | 17 -> parse_udp (Cstruct.shift p offset)
            | _ -> raise (Invalid_argument "")
        ) in
        Some { time ; ethernet ; ipv4 ; l4 }
    with
        Invalid_argument _ -> None
            (* ...some packets in CAIDA traces are not as big as we expect which causes Cstruct to throw this: just ignore for now *)



