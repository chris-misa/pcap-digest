(*
 * Implementation of window-based operations
 *)

open Printf
open Pcap_digest

(*
 * Keep track of and count all destinations
 *)
module Dsts =
struct
    type t = IPv4Set.t

    let init () = 
        IPv4Set.empty

    let proc {ipv4 ; _} m =
        IPv4Set.add ipv4.dst m

    let final m =
        IPv4Set.fold (fun ip _ -> printf "%s\n" (Ipaddr.V4.to_string ip)) m () ;
        printf "total: %d\n" (IPv4Set.cardinal m)
end
