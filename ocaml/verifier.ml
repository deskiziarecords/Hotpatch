(* ocaml verifier *)

open Printf

let load_be64 buf off =
  let open Int64 in
  let (lor) = logor in
  let (lsl) = shift_left in
  let b i = of_int (char_of_int (int_of_char (Bytes.get buf (off + i))) |> int_of_char) in
  (b 0 lsl 56) lor (b 1 lsl 48) lor (b 2 lsl 40) lor (b 3 lsl 32) lor
  (b 4 lsl 24) lor (b 5 lsl 16) lor (b 6 lsl 8) lor (b 7)

let verify cert expected_pubhash max_wcet max_budget max_agents max_epsilon =
  let hash_ok =
    let rec check i =
      if i = 32 then true
      else if (Bytes.get cert i) <> (Bytes.get expected_pubhash i) then false
      else check (i + 1)
    in
    check 0
  in
  let wcet = load_be64 cert 0xB0 in
  let deltaB = load_be64 cert 0xB8 in
  let agents = int_of_char (Bytes.get cert 0xC0) in
  let epsilon = int_of_char (Bytes.get cert 0xC1) in

  let wcet_ok = wcet <= max_wcet in
  let budget_ok = deltaB <= max_budget in
  let agents_ok = agents <= max_agents in
  let epsilon_ok = epsilon <= max_epsilon in

  hash_ok && wcet_ok && budget_ok && agents_ok && epsilon_ok

let hex_to_bytes s =
  let n = String.length s / 2 in
  let b = Bytes.create n in
  for i = 0 to n - 1 do
    let x = int_of_string ("0x" ^ String.sub s (i * 2) 2) in
    Bytes.set b i (char_of_int x)
  done;
  b

let () =
  if Array.length Sys.argv <> 7 then (
    eprintf "Usage: %s <cert_path> <pubhash_hex> <max_wcet> <max_budget> <max_agents> <max_epsilon>\n" Sys.argv.(0);
    exit 2
  );
  let cert_path = Sys.argv.(1) in
  let pubhash_hex = Sys.argv.(2) in
  let max_wcet = Int64.of_string Sys.argv.(3) in
  let max_budget = Int64.of_string Sys.argv.(4) in
  let max_agents = int_of_string Sys.argv.(5) in
  let max_epsilon = int_of_string Sys.argv.(6) in

  let expected_pubhash = hex_to_bytes pubhash_hex in
  let ic = open_in_bin cert_path in
  let cert = Bytes.create 512 in
  really_input ic cert 0 512;
  close_in ic;

  if verify cert expected_pubhash max_wcet max_budget max_agents max_epsilon then (
    printf "VERIFIED\n";
    exit 0
  ) else (
    printf "REJECTED\n";
    exit 1
  )
