(*
 * Main entry point and implementation for simple header-dump operation
 *)
open Pcap
open Printf
open Option
open Pcap_digest

(*
 * Main mapping from cli operation strings to associated implementations
 * Add new operation constructors here
 *)
module OpsMap = Map.Make(String)
let ops_map = OpsMap.of_seq (List.to_seq [
    ("dump", Dump.dump) ;
    ("total.srcs", Totals.srcs) ;
    ("total.dsts", Totals.dsts) ;
    ("window.srcs", Windows.(windows [distinct (fun p -> p.ipv4.src) "srcs"])) ;
    ("window.dsts", Windows.(windows [distinct (fun p -> p.ipv4.dst) "dsts"])) ;
    ("window.srcdsts", Windows.(windows [distinct (fun p -> (p.ipv4.src, p.ipv4.dst)) "srcdsts"])) ;
    ("window.srcs.dsts", Windows.(windows [distinct (fun p -> p.ipv4.src) "srcs" ; distinct (fun p -> p.ipv4.dst) "dsts"])) ;
    ("window.srcdstlens", Windows.(windows [distinct (fun p -> (p.ipv4.src, p.ipv4.dst, p.ipv4.len)) "srcdstlens"])) ;
    ("window.all", Windows.(windows [
            distinct (fun p -> p.ipv4.src) "srcs" ;
            distinct (fun p -> p.ipv4.dst) "dsts" ;
            distinct (fun p -> (p.ipv4.src, p.ipv4.dst)) "srcdsts" ;
            distinct (fun p -> (p.ipv4.src, p.ipv4.dst, p.ipv4.len)) "srcdstlens" ;
            distinct (fun p -> (p.ipv4.src, p.l4.dport)) "srcdports" ;
            distinct (fun p -> (p.ipv4.src, p.ipv4.dst, p.l4.sport)) "srcdstsports" ;
        ])) ;
    ("psample.srcs", Windows.(windows [
            Sampling.psample 0.5 (distinct (fun p -> p.ipv4.src) "src.50") ;
            Sampling.psample 0.75 (distinct (fun p -> p.ipv4.src) "src.75") ;
            distinct (fun p -> p.ipv4.src) "src.100" ;
        ])) ;
    ("fsample.srcs", Windows.(windows [
            Sampling.fsample 0.5 (distinct (fun p -> p.ipv4.src) "src.50") ;
            Sampling.fsample 0.75 (distinct (fun p -> p.ipv4.src) "src.75") ;
            distinct (fun p -> p.ipv4.src) "src.100" ;
        ])) ;
])

let fold_file ops_string out_prefix filename = 
    
    (* Parse operation list and look up modules *)
    let op_keys = String.split_on_char ',' ops_string in
    let op_cons =
        op_keys |>
        (List.filter_map
            (fun k ->
            match OpsMap.find_opt k ops_map with
            | Some op_con -> Some op_con
            | None -> printf "WARNING: ignoring unknown operation \"%s\"\n" k; None
            )
        ) in

    (* Open pcap file *)
    let h, buf = read_header filename in
    let module H = (val h: Pcap.HDR) in
    let header, body = Cstruct.split buf sizeof_pcap_header in
    let network = Int32.to_int (H.get_pcap_header_network header) in

    (* printf "header.network: %lu\n" (H.get_pcap_header_network header); *)

    (* Main fold *)
    (List.combine op_keys op_cons) |>
    (List.map (fun (op_key, op_con) -> op_con (open_out (out_prefix ^ op_key ^ ".out")))) |>
    (Cstruct.fold
        (fun ops (hdr,pkt) -> (
        match (parse_pkt network h hdr pkt) with
        | Some p -> List.iter (fun op -> op.proc p) ops
        | None -> ());
        ops
        )
        (packets h body)
    ) |>
    (List.iter (fun op -> printf "%s : %s\n" op.name (string_of_op_result (op.final ()))))

(*
 * Main entrypoint
 *)
let () =
    if Array.length Sys.argv = 4
    then fold_file Sys.argv.(1) Sys.argv.(2) Sys.argv.(3)
    else printf "Expected <operation list> <outfile prefix> <capture file> as first arguments.\n"
