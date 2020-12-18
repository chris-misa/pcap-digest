
open Pcap
open Printf
open Option
open Pcap_digest

(*
 * Each operation must provide implementation for each of these fields
 *)
type 'a pcap_op = {
    proc : (module HDR) -> Cstruct.t -> Cstruct.t -> 'a -> 'a ;
    init : 'a ;
    final : 'a -> unit ;
}

(*
 * Simple operation to dump some header fields for each packet
 *)
let proc_dump h hdr pkt () =
    let module H = (val h: HDR) in
    match parse_pkt pkt with
    | Some {ethernet ; ipv4 ; l4} ->
        printf "[%lu.%06lu] ether %s -> %s | ip %s -> %s (%d) | l4 %s %d -> %d\n"
            (H.get_pcap_packet_ts_sec hdr)
            (H.get_pcap_packet_ts_usec hdr)
            (mac_to_string ethernet.src)
            (mac_to_string ethernet.dst)
            (Ipaddr.V4.to_string ipv4.src)
            (Ipaddr.V4.to_string ipv4.dst)
            ipv4.proto
            (tcp_flags_to_string l4.flags)
            l4.sport
            l4.dport
    | None -> 
        printf "failed to parse\n"

let final_dump _ =
    printf "Done."


(*
 * Main mapping from cli operation strings to associated implementation functions
 * Add new operations here
 *)
module OpsMap = Map.Make(String)
let ops_map = OpsMap.of_seq (List.to_seq [
    ("dump", {
        proc = proc_dump ;
        init = () ;
        final = final_dump ;
    }) ;
])


let fold_file op filename = 
    match OpsMap.find_opt op ops_map with
    | Some { proc ; init ; final } ->
        let h, buf = read_header filename in
        let _, body = Cstruct.split buf sizeof_pcap_header in
        final (Cstruct.fold (fun a (hdr,pkt) -> proc h hdr pkt a) (packets h body) init)
    | None -> printf "Unknown operation \"%s\"\n" op

(*
 * Main entrypoint
 *)
let () =
    if Array.length Sys.argv = 3
    then fold_file Sys.argv.(1) Sys.argv.(2)
    else printf "Expected <operation> <capture file> as first arguments.\n"
