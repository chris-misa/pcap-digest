(*
 * Implementation of window-based operations
 *)

open Printf
open Pcap_digest

let epoch_dur = 2.


let windows ops () =
    let os = ref (List.map (fun op_con -> op_con ()) ops) in
    let epoch = ref 0. in
    {
        proc = (fun p ->
            if !epoch = 0.
            then epoch := p.time +. epoch_dur
            else if p.time >= !epoch
            then (
                printf "%f," !epoch ;
                List.iter (fun o -> o.final ()) !os ;
                printf "\n" ;
                epoch := !epoch +. epoch_dur ;
                os := (List.map (fun op_con -> op_con ()) ops) ;
            );
            List.iter (fun o -> o.proc p) !os ;
        );
        final = (fun () -> ()) ;
    }


let srcs () =
    let m = ref IPv4Set.empty in
    {
        proc = (fun {ipv4 ; _} -> m := IPv4Set.add ipv4.src !m) ;
        final = (fun () -> printf "%d," (IPv4Set.cardinal !m)) ;
    }

let dsts () =
    let m = ref IPv4Set.empty in
    {
        proc = (fun {ipv4 ; _} -> m := IPv4Set.add ipv4.dst !m) ;
        final = (fun () -> printf "%d," (IPv4Set.cardinal !m)) ;
    }

module IPv4TupleSet = Set.Make(
    struct
        type t = Ipaddr.V4.t * Ipaddr.V4.t
        let compare (x1,y1) (x2,y2) = compare (x1,y1) (x2,y2)
    end
)

let src_dsts () =
    let m = ref IPv4TupleSet.empty in
    {
        proc = (fun {ipv4 ; _} -> m := IPv4TupleSet.add (ipv4.src,ipv4.dst) !m) ;
        final = (fun () -> printf "%d," (IPv4TupleSet.cardinal !m)) ;
    }
