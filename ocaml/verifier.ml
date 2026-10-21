(* ocaml verifier: reference model for src/runtime/verify_cert.c *)

open Printf

let load_be64 buf off =
  let open Int64 in
  let (lor) = logor in
  let (lsl) = shift_left in
  let b i = of_int (int_of_char (Bytes.get buf (off + i))) in
  (b 0 lsl 56) lor (b 1 lsl 48) lor (b 2 lsl 40) lor (b 3 lsl 32) lor
  (b 4 lsl 24) lor (b 5 lsl 16) lor (b 6 lsl 8) lor (b 7)

(* Certificate fields are u64; Int64 is signed, so compare unsigned. *)
let u64_le x y = Int64.unsigned_compare x y <= 0
let u64_lt x y = Int64.unsigned_compare x y < 0

let verify cert key_id max_wcet max_budget max_agents max_leakage last_epoch =
  let key_ok =
    let rec check i =
      if i = 32 then true
      else if (Bytes.get cert i) <> (Bytes.get key_id i) then false
      else check (i + 1)
    in
    check 0
  in
  let wcet = load_be64 cert 0xB0 in
  let deltaB = load_be64 cert 0xB8 in
  let agents = int_of_char (Bytes.get cert 0xC0) in
  let leakage = int_of_char (Bytes.get cert 0xC1) in
  let epoch = load_be64 cert 0xC2 in

  let wcet_ok = u64_le wcet max_wcet in
  let budget_ok = u64_le deltaB max_budget in
  let agents_ok = agents <= max_agents in
  let leakage_ok = leakage <= max_leakage in
  let epoch_ok = u64_lt last_epoch epoch in

  key_ok && wcet_ok && budget_ok && agents_ok && leakage_ok && epoch_ok

let hex_to_bytes s =
  let n = String.length s / 2 in
  let b = Bytes.create n in
  for i = 0 to n - 1 do
    let x = int_of_string ("0x" ^ String.sub s (i * 2) 2) in
    Bytes.set b i (char_of_int x)
  done;
  b

(* Unsigned decimal, matching strtoull for in-range values. *)
let u64_of_string s = Int64.of_string ("0u" ^ s)

(* C casts the u8 ceilings with (uint8_t)atoi; mirror the truncation. *)
let u8_of_string s = int_of_string s land 0xFF

let () =
  if Array.length Sys.argv <> 8 then (
    eprintf "Usage: %s <cert_path> <key_id_hex> <max_wcet_ns> <max_budget> <max_agents> <max_leakage> <last_epoch>\n" Sys.argv.(0);
    exit 2
  );
  let cert_path = Sys.argv.(1) in
  let key_id_hex = Sys.argv.(2) in
  let max_wcet = u64_of_string Sys.argv.(3) in
  let max_budget = u64_of_string Sys.argv.(4) in
  let max_agents = u8_of_string Sys.argv.(5) in
  let max_leakage = u8_of_string Sys.argv.(6) in
  let last_epoch = u64_of_string Sys.argv.(7) in

  let key_id = hex_to_bytes key_id_hex in
  let ic = open_in_bin cert_path in
  let cert = Bytes.create 512 in
  really_input ic cert 0 512;
  close_in ic;

  if verify cert key_id max_wcet max_budget max_agents max_leakage last_epoch then (
    printf "VERIFIED\n";
    exit 0
  ) else (
    printf "REJECTED\n";
    exit 1
  )
