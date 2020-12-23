(*
 * Implementation of window-based operations
 *)

open Printf
open Pcap_digest

let epoch_dur = 2.
let init_hash_size = 10000

(*
 * Runs a list of operations per-epoch, calling final () (which should also reset state) after each epoch
 *)
let windows ops outc =
    let os = List.map (fun op_con -> op_con outc) ops in
    let epoch = ref 0.0 in
    fprintf outc "time," ;
    List.iter (fun o -> fprintf outc "%s," o.name) os;
    fprintf outc "\n" ;
    {
        name = "window" ;
        proc = (fun p ->
            if !epoch = 0.0
            then epoch := p.time +. epoch_dur
            else if p.time >= !epoch
            then (
                fprintf outc "%f," !epoch ;
                List.iter (fun o -> fprintf outc "%s," (string_of_op_result (o.final ()))) os ;
                fprintf outc "\n" ;
                epoch := !epoch +. epoch_dur ;
            );
            List.iter (fun o -> o.proc p) os ;
        );
        final = (fun () -> close_out outc; Empty) ;
    }


(*
 * Returns a count of distinct elements
 * Distinction is determined by the return value of f on each packet
 *)
let distinct f name _ = 
    let m = Hashtbl.create init_hash_size in
    {
        name = name ;
        proc = (fun p -> Hashtbl.replace m (f p) true) ;
        final = (fun () ->
            let res = Hashtbl.length m in
            Hashtbl.clear m ;
            Int res
        ) ;
    }


