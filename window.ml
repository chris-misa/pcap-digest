(*
 * Implementation of window-based operations
 *)

open Pcap
open Printf
open Pcap_digest


(*
 * Initially, just count the number of all destinations
 *)
module Dsts =
struct
    module IPv4Set = Set.Make(Ipaddr.V4)
    type t = IPv4Set.t

    let init () = 
        IPv4Set.empty

    let proc h _ pkt m =
        let module H = (val h: HDR) in
        match parse_pkt pkt with
        | Some {ipv4 ; _} ->
            IPv4Set.add ipv4.dst m
        | None ->
            printf "failed to parse\n" ; m

    let final m =
        IPv4Set.fold (fun ip _ -> printf "%s\n" (Ipaddr.V4.to_string ip)) m () ;
        printf "total: %d\n" (IPv4Set.cardinal m)
end
