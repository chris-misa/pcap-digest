(* Implementation of different sampling techniques *)

(* open Printf *)
open Pcap_digest

let init_hash_size = 10000

let bernoulli p = Random.float 1.0 < p

(* Simple packet-level sample with no correction *)
let psample ratio op_con outc = 
    let o = op_con outc in
    {
        name = "psample." ^ o.name ;
        proc = (fun p -> if bernoulli ratio then o.proc p) ;
        (* final = (fun () -> Float ((1.0 /. ratio) *. (float_of_op_result (o.final ())))) ; *)
        final = (fun () -> o.final ()) ;
    }

(* Simple five-tuple flow sample with no correction *)
let fsample ratio op_con outc =
    let o = op_con outc in
    let m = Hashtbl.create init_hash_size in
    let get_key p = (p.ipv4.src, p.ipv4.dst, p.ipv4.proto, p.l4.sport, p.l4.dport) in
    {
        name = "fsample." ^ o.name ;
        proc = (fun p ->
            let key = get_key p in
            if Hashtbl.mem m key
            then o.proc p
            else if bernoulli ratio
            then (Hashtbl.add m key true ; o.proc p)) ;
        final = (fun () -> (Hashtbl.clear m ; o.final ())) ;
    }
        
