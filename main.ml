(*
 * Main entry point and implementation for simple header-dump operation
 *)
open Pcap
open Printf
open Option
open Pcap_digest

(*
 * Example implementation of a PcapOperation module to dump per-packet header info
 *)
let dump () =
    let a = ref 0 in
    {
        proc  = (fun {time ; ethernet ; ipv4 ; l4} ->
            (match ethernet with
            | Some ether ->
                printf "%d [%f] ether %s -> %s | ip %s -> %s (%d) | l4 %s %d -> %d\n"
                    !a
                    time
                    (mac_to_string ether.src)
                    (mac_to_string ether.dst)
                    (Ipaddr.V4.to_string ipv4.src)
                    (Ipaddr.V4.to_string ipv4.dst)
                    ipv4.proto
                    (tcp_flags_to_string l4.flags)
                    l4.sport
                    l4.dport
            | None ->
                printf "%d [%f] ip %s -> %s (%d) | l4 %s %d -> %d\n"
                    !a
                    time
                    (Ipaddr.V4.to_string ipv4.src)
                    (Ipaddr.V4.to_string ipv4.dst)
                    ipv4.proto
                    (tcp_flags_to_string l4.flags)
                    l4.sport
                    l4.dport
            );
            incr a) ;
        final = (fun () -> printf "Done.") ;
    }

(*
 * Main mapping from cli operation strings to associated implementations
 * Add new operations here
 *)
module OpsMap = Map.Make(String)
let ops_map = OpsMap.of_seq (List.to_seq [
    ("dump", dump) ;
    ("window.dsts", Windows.window Windows.dsts) ;
    ("total.dsts", Totals.dsts) ;
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
    | Some op_cons ->
        let h, buf = read_header filename in
        let module H = (val h: Pcap.HDR) in
        let header, body = Cstruct.split buf sizeof_pcap_header in
        let network = Int32.to_int (H.get_pcap_header_network header) in
        (Cstruct.fold
            (fun o (hdr,pkt) -> match (parse_pkt network h hdr pkt) with
                | Some p -> (o.proc p ; o)
                | None -> o)
            (packets h body)
            (op_cons ()))
        |> (fun {final ; _ } -> final ())
    | None -> printf "Unknown operation \"%s\"\n" op

(*
 * Main entrypoint
 *)
let () =
    if Array.length Sys.argv = 3
    then fold_file Sys.argv.(1) Sys.argv.(2)
    else printf "Expected <operation> <capture file> as first arguments.\n"
