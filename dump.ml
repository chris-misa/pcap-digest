open Printf
open Pcap_digest

(*
 * Example operation constructor to dump per-packet header info
 *)
let dump outc =
    let a = ref 0 in
    {
        name = "dump" ;
        proc  = (fun {time ; ethernet ; ipv4 ; l4} ->
            (match ethernet with
            | Some ether ->
                fprintf outc "%d [%f] ether %s -> %s | ip %s -> %s (%d) | l4 %s %d -> %d\n"
                    !a
                    time
                    (mac_to_string ether.src)
                    (mac_to_string ether.dst)
                    (Ipaddr.V4.to_string ipv4.src)
                    (Ipaddr.V4.to_string ipv4.dst)
                    ipv4.proto
                    (tcp_flags_to_string l4.flags)
                    l4.sport
                    l4.dport
            | None ->
                fprintf outc "%d [%f] ip %s -> %s (%d) | l4 %s %d -> %d\n"
                    !a
                    time
                    (Ipaddr.V4.to_string ipv4.src)
                    (Ipaddr.V4.to_string ipv4.dst)
                    ipv4.proto
                    (tcp_flags_to_string l4.flags)
                    l4.sport
                    l4.dport
            );
            incr a) ;
        final = (fun () -> close_out outc) ;
    }
