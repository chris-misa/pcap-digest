(*
 * Implementation of window-based operations
 *)

open Printf
open Pcap_digest

let epoch_dur = 2.


(* Driver for WindowOperation modules *)
module Window (Op : PcapOperation) = 
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
            else (printf "%f " epoch ; Op.final m ; printf "\n" ; (epoch +. epoch_dur, Op.proc p (Op.init ()))::(epoch,m)::tl)
        | [] -> failwith "Internal error: uninitialized state!"

    let final _ = ()
end


(* WindowOperation to count distinct destinations *)
module Dsts =
struct
    type t = IPv4Set.t

    let init () =
        IPv4Set.empty

    let proc {ipv4 ; _} m =
        IPv4Set.add ipv4.dst m

    let final m =
        printf "%d" (IPv4Set.cardinal m)

end
