(*
 * Implementation of window-based operations
 *)

open Printf
open Pcap_digest

let epoch_dur = 2.


let window op () =
    let o = ref (op ()) in
    let epoch = ref 0. in
    {
        proc = (fun p ->
            if !epoch = 0.
            then epoch := p.time +. epoch_dur
            else if p.time >= !epoch
            then (
                printf "%f," !epoch ;
                (!o).final () ;
                printf "\n" ;
                epoch := !epoch +. epoch_dur ;
                o := op () ;
            );
            (!o).proc p ;
        );
        final = (fun () -> ()) ;
    }


let dsts () =
    let m = ref IPv4Set.empty in
    {
        proc = (fun {ipv4 ; _} -> m := IPv4Set.add ipv4.dst !m) ;
        final = (fun () -> printf "dsts,%d" (IPv4Set.cardinal !m)) ;
    }

let srcs () =
    let m = ref IPv4Set.empty in
    {
        proc = (fun {ipv4 ; _} -> m := IPv4Set.add ipv4.src !m) ;
        final = (fun () -> printf "srcs,%d" (IPv4Set.cardinal !m)) ;
    }
