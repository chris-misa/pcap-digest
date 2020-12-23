(*
 * Implementation of window-based operations
 *)

open Printf
open Pcap_digest

(*
 * Keep track of and count all sources
 *)
let srcs outc =
    let m = ref IPv4Set.empty in
    {
        name = "srcs" ;
        proc = (fun {ipv4 ; _} -> m := IPv4Set.add ipv4.src !m) ;
        final = (fun () ->
            let res = IPv4Set.cardinal !m in
            IPv4Set.fold (fun ip _ -> fprintf outc "%s\n" (Ipaddr.V4.to_string ip)) !m () ;
            close_out outc ;
            Int res
        ) ;
    }
(*
 * Keep track of and count all destinations
 *)
let dsts outc =
    let m = ref IPv4Set.empty in
    {
        name = "dsts" ;
        proc = (fun {ipv4 ; _} -> m := IPv4Set.add ipv4.dst !m) ;
        final = (fun () ->
            let res = IPv4Set.cardinal !m in
            IPv4Set.fold (fun ip _ -> fprintf outc "%s\n" (Ipaddr.V4.to_string ip)) !m () ;
            close_out outc ;
            Int res
        ) ;
    }
