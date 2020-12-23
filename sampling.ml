(* Implementation of different sampling techniques *)

(* open Printf *)
open Pcap_digest

(* Simple packet-level sample with crude correction *)
let psample ratio op_con outc = 
    let o = op_con outc in
    {
        name = "psample." ^ o.name ;
        proc = (fun p -> if Random.float 1.0 < ratio then o.proc p) ;
        final = (fun () -> Float ((1.0 /. ratio) *. (float_of_op_result (o.final ())))) ;
    }
