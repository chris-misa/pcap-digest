(*
 * Main entry point and implementation for simple header-dump operation
 *)
open Pcap
open Printf
open Option
open Pcap_digest
open Windows

(*
 * Example implementation of a PcapOperation module to dump per-packet header info
 *)
module DumpOperation =
struct
    type t = int
    let init () = 1
    let proc {time ; ethernet ; ipv4 ; l4} a =
        printf "%d [%f] ether %s -> %s | ip %s -> %s (%d) | l4 %s %d -> %d\n"
            a
            time
            (mac_to_string ethernet.src)
            (mac_to_string ethernet.dst)
            (Ipaddr.V4.to_string ipv4.src)
            (Ipaddr.V4.to_string ipv4.dst)
            ipv4.proto
            (tcp_flags_to_string l4.flags)
            l4.sport
            l4.dport;
        a + 1

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
    ("window.dsts", (module Window(Dsts) : PcapOperation)) ;
    ("total.dsts", (module Totals.Dsts : PcapOperation)) ;
])

let print_type filename = 
    let h, buf = read_header filename in
    let module H = (val h: Pcap.HDR) in
    let header, _ = Cstruct.split buf sizeof_pcap_header in
    printf "header.network: %lu\n" (H.get_pcap_header_network header)

let fold_file op filename = 
    if op = "network.type" then print_type filename
    else
    match OpsMap.find_opt op ops_map with
    | Some (module Mod) ->
        let h, buf = read_header filename in
        let module H = (val h: Pcap.HDR) in
        let _, body = Cstruct.split buf sizeof_pcap_header in
        (Cstruct.fold
            (fun a (hdr,pkt) -> match (parse_pkt h hdr pkt) with
                | Some p -> Mod.proc p a
                | None -> a)
            (packets h body)
            (Mod.init ()))
        |> Mod.final
    | None -> printf "Unknown operation \"%s\"\n" op

(*
 * Main entrypoint
 *)
let () =
    if Array.length Sys.argv = 3
    then fold_file Sys.argv.(1) Sys.argv.(2)
    else printf "Expected <operation> <capture file> as first arguments.\n"
