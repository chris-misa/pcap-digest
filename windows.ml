(*
 * Implementation of window-based operations
 *)

open Printf
open Pcap_digest

let epoch_dur = 2.


module type WindowOperation = 
sig
    (* Intermediate type produced in fold *)
    type t

    (* Return the initial value (of each epoch) *)
    val init : unit -> t 

    (* Process one packet *)
    val proc : pkt -> t -> t

    (* Print summary after fold (of each epoch) completes *)
    val final : (float * t) list -> unit
end

(* Driver for WindowOperation modules *)
module Window (Op : WindowOperation) = 
struct
    type t = (float * Op.t) list

    let init () = 
        [(0., Op.init ())]

    let proc p state =
        match state with
        | ((epoch,m)::tl) ->
            let new_m = Op.proc p m in
            if epoch = 0.
            then (p.time +. epoch_dur, new_m)::tl
            else if p.time < epoch
            then (epoch, new_m)::tl
            else (epoch +. epoch_dur, Op.proc p (Op.init ()))::(epoch,m)::tl
        | [] -> failwith "Internal error: uninitialized state!"

    let final state =
        Op.final state
end


(* WindowOperation to count distinct destinations *)
module Dsts =
struct
    type t = IPv4Set.t

    let init () = IPv4Set.empty

    let proc {ipv4 ; _} m =
        IPv4Set.add ipv4.dst m

    let final state =
        List.fold_left (fun _ (epoch,m) -> (printf "%f %d\n" epoch (IPv4Set.cardinal m)))
            () (List.rev state)
end
