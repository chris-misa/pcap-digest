(*
 * Implementation of window-based operations
 *)

open Pcap
open Printf
open Pcap_digest

let epoch_dur = 2.

(*
 * Keep track of and count destinations in each epoch
 * ... probably some way to make this into generic per-window operations
 *)
module Dsts =
struct
    module IPv4Set = Set.Make(Ipaddr.V4)
    type t = (float * IPv4Set.t) list

    let init () = 
        [(0., IPv4Set.empty)]

    let proc h hdr pkt state =
        match state with
        | ((epoch,m)::tl) -> (
            let module H = (val h: HDR) in
            match parse_pkt pkt with
            | Some {ipv4 ; _} ->
                let cur = (Int32.to_float (H.get_pcap_packet_ts_sec hdr)) +. (Int32.to_float (H.get_pcap_packet_ts_usec hdr)) /. 1000000. in
                let new_m = IPv4Set.add ipv4.dst m in
                if epoch = 0.
                then (cur +. epoch_dur, new_m)::tl
                else if cur < epoch
                then (epoch, new_m)::tl
                else (epoch +. epoch_dur, IPv4Set.singleton ipv4.dst)::(epoch,m)::tl
            | None ->
                printf "failed to parse\n" ; (epoch,m)::tl
            )
        | [] -> failwith "Internal error: uninitialized state!"

    let final state =
        List.fold_left (fun _ (epoch,m) -> (printf "---- Epoch %f ----\n" epoch ; 
                IPv4Set.fold (fun ip _ -> printf "%s\n" (Ipaddr.V4.to_string ip)) m () ;
                printf "total: %d\n" (IPv4Set.cardinal m)))
            () (List.rev state)
    
end
