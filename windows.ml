(*
 * Implementation of window-based operations
 *)

open Printf
open Pcap_digest

let epoch_dur = 2.

(*
 * Runs a list of operations per-epoch, calling final () and resetting their state after each epoch
 *)
let windows ops outc =
    let call_con = fun op_con -> op_con outc in
    let os = ref (List.map call_con ops) in
    let epoch = ref 0. in
    fprintf outc "time," ;
    List.iter (fun o -> fprintf outc "%s," o.name) !os;
    fprintf outc "\n" ;
    {
        name = "window" ;
        proc = (fun p ->
            if !epoch = 0.
            then epoch := p.time +. epoch_dur
            else if p.time >= !epoch
            then (
                fprintf outc "%f," !epoch ;
                List.iter (fun o -> o.final ()) !os ;
                fprintf outc "\n" ;
                epoch := !epoch +. epoch_dur ;
                os := (List.map call_con ops) ;
            );
            List.iter (fun o -> o.proc p) !os ;
        );
        final = (fun () -> close_out outc) ;
    }

(* Count distinct sources *)
let srcs outc =
    let m = ref IPv4Set.empty in
    {
        name = "srcs" ;
        proc = (fun {ipv4 ; _} -> m := IPv4Set.add ipv4.src !m) ;
        final = (fun () -> fprintf outc "%d," (IPv4Set.cardinal !m)) ;
    }

(* Count distinct destinations *)
let dsts outc =
    let m = ref IPv4Set.empty in
    {
        name = "dsts" ;
        proc = (fun {ipv4 ; _} -> m := IPv4Set.add ipv4.dst !m) ;
        final = (fun () -> fprintf outc "%d," (IPv4Set.cardinal !m)) ;
    }


(* Count distinct source, destination pairs *)
let src_dsts outc =
    let module IPv4TupleSet = Set.Make(
        struct
            type t = Ipaddr.V4.t * Ipaddr.V4.t
            let compare a b = compare a b
        end
    ) in
    let m = ref IPv4TupleSet.empty in
    {
        name = "srcdsts" ;
        proc = (fun {ipv4 ; _} -> m := IPv4TupleSet.add (ipv4.src, ipv4.dst) !m) ;
        final = (fun () -> fprintf outc "%d," (IPv4TupleSet.cardinal !m)) ;
    }

(* Count distinct source, destination, packet size tuples *)
let src_dst_lens outc = 
    let module MSet = Set.Make(
        struct
            type t = Ipaddr.V4.t * Ipaddr.V4.t * int
            let compare a b = compare a b
        end
    ) in
    let m = ref MSet.empty in
    {
        name = "srcdstlens" ;
        proc = (fun {ipv4 ; _} -> m := MSet.add (ipv4.src, ipv4.dst, ipv4.len) !m) ;
        final = (fun () -> fprintf outc "%d," (MSet.cardinal !m)) ;
    }

(* Count distinct source, destination port pairs *)
let src_dports outc = 
    let module MSet = Set.Make(
        struct
            type t = Ipaddr.V4.t * int
            let compare a b = compare a b
        end
    ) in
    let m = ref MSet.empty in
    {
        name = "srcdport" ;
        proc = (fun {ipv4 ; l4 ; _} -> m := MSet.add (ipv4.src, l4.dport) !m) ;
        final = (fun () -> fprintf outc "%d," (MSet.cardinal !m)) ;
    }


(* Count distinct source, destination, source port pairs *)
let src_dst_dports outc = 
    let module MSet = Set.Make(
        struct
            type t = Ipaddr.V4.t * Ipaddr.V4.t * int
            let compare a b = compare a b
        end
    ) in
    let m = ref MSet.empty in
    {
        name = "srcdstsport" ;
        proc = (fun {ipv4 ; l4 ; _} -> m := MSet.add (ipv4.src, ipv4.dst, l4.sport) !m) ;
        final = (fun () -> fprintf outc "%d," (MSet.cardinal !m)) ;
    }



(* ..... should go for a generic count distinct suboperation parameterized by distinct key *)
