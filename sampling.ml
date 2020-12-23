(* Implementation of different sampling techniques *)

(* open Printf *)
open Pcap_digest

(* bad bad bad global variables....need to merge with the same in windows.ml *)
let epoch_dur = 2.
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
            match Hashtbl.find_opt m key with
            | Some true -> o.proc p
            | Some false -> ()
            | None ->
                if bernoulli ratio
                then (Hashtbl.add m key true ; o.proc p)
                else Hashtbl.add m key false
        ) ;
        final = (fun () -> (Hashtbl.clear m ; o.final ())) ;
    }
        
let shuffle a =
    let n = Array.length a in
    for i = n - 1 downto 1 do
        let k = Random.int (i+1) in
        let x = a.(k) in
        a.(k) <- a.(i);
        a.(i) <- x
    done ;
    a

(* Simple sub-epoch sampling: chooses num_samples out of num_subepochs to execute operation in *)
let esample num_subepochs num_samples op_con outc =
    let o = op_con outc in
    let make_schedule () = shuffle (Array.init num_subepochs (fun i -> i < num_samples)) in
    let subepoch_dur = epoch_dur /. (float_of_int num_subepochs) in
    let schedule = ref (make_schedule ()) in
    let epoch = ref 0.0 in
    let i = ref 0 in
    {
        name = "esample." ^ o.name ;
        proc = (fun p ->
            if !epoch = 0.0
            then epoch := p.time +. subepoch_dur
            else if p.time >= !epoch
            then (
                incr i ;
                epoch := !epoch +. subepoch_dur
            ) ;
            if (!schedule).(!i)
            then o.proc p
        ) ;
        final = (fun () -> (
            schedule := make_schedule () ;
            epoch := 0.0 ;
            i := 0 ;
            o.final ()
        )) ;
    }
