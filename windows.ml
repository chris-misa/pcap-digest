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


let srcs outc =
    let m = ref IPv4Set.empty in
    {
        name = "srcs" ;
        proc = (fun {ipv4 ; _} -> m := IPv4Set.add ipv4.src !m) ;
        final = (fun () -> fprintf outc "%d," (IPv4Set.cardinal !m)) ;
    }

let dsts outc =
    let m = ref IPv4Set.empty in
    {
        name = "dsts" ;
        proc = (fun {ipv4 ; _} -> m := IPv4Set.add ipv4.dst !m) ;
        final = (fun () -> fprintf outc "%d," (IPv4Set.cardinal !m)) ;
    }

module IPv4TupleSet = Set.Make(
    struct
        type t = Ipaddr.V4.t * Ipaddr.V4.t
        let compare (x1,y1) (x2,y2) = compare (x1,y1) (x2,y2)
    end
)

let src_dsts outc =
    let m = ref IPv4TupleSet.empty in
    {
        name = "srcdsts" ;
        proc = (fun {ipv4 ; _} -> m := IPv4TupleSet.add (ipv4.src,ipv4.dst) !m) ;
        final = (fun () -> fprintf outc "%d," (IPv4TupleSet.cardinal !m)) ;
    }
