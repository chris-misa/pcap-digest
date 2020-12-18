(*
 * Main entry point and implementation for simple header-dump operation
 *)
open Pcap
open Printf
open Option
open Pcap_digest

(*
 * Simple operation to dump some header fields for each packet
 *)
module DumpOperation =
struct
    type t = unit
    let init () = ()
    let proc h hdr pkt () =
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

    let final _ =
        printf "Done."
end


(*
 * Main mapping from cli operation strings to associated implementations
 * Add new operations here
 *)
module OpsMap = Map.Make(String)
let ops_map = OpsMap.of_seq (List.to_seq [
    ("dump", (module DumpOperation : PcapOperation)) ;
    ("dsts", (module Window.Dsts : PcapOperation)) ;
])


let fold_file op filename = 
    match OpsMap.find_opt op ops_map with
    | Some (module Mod) ->
        let h, buf = read_header filename in
        let _, body = Cstruct.split buf sizeof_pcap_header in
        Mod.final (Cstruct.fold (fun a (hdr,pkt) -> Mod.proc h hdr pkt a) (packets h body) (Mod.init ()))
    | None -> printf "Unknown operation \"%s\"\n" op

(*
 * Main entrypoint
 *)
let () =
    if Array.length Sys.argv = 3
    then fold_file Sys.argv.(1) Sys.argv.(2)
    else printf "Expected <operation> <capture file> as first arguments.\n"
