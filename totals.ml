(*
 * Implementation of window-based operations
 *)

open Printf
open Pcap_digest

(*
 * Keep track of and count all destinations
 *)
let dsts outc =
    let m = ref IPv4Set.empty in
    {
        proc = (fun {ipv4 ; _} -> m := IPv4Set.add ipv4.dst !m) ;
        final = (fun () ->
            IPv4Set.fold (fun ip _ -> fprintf outc "%s\n" (Ipaddr.V4.to_string ip)) !m () ;
            fprintf outc "total: %d\n" (IPv4Set.cardinal !m) ;
            close_out outc ;
        ) ;
    }
