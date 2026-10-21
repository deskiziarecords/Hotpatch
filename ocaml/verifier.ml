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

(* SHA-256 (FIPS 180-4) on native ints masked to 32 bits; needs 64-bit OCaml. *)
let sha256_k = [|
  0x428a2f98; 0x71374491; 0xb5c0fbcf; 0xe9b5dba5; 0x3956c25b; 0x59f111f1; 0x923f82a4; 0xab1c5ed5;
  0xd807aa98; 0x12835b01; 0x243185be; 0x550c7dc3; 0x72be5d74; 0x80deb1fe; 0x9bdc06a7; 0xc19bf174;
  0xe49b69c1; 0xefbe4786; 0x0fc19dc6; 0x240ca1cc; 0x2de92c6f; 0x4a7484aa; 0x5cb0a9dc; 0x76f988da;
  0x983e5152; 0xa831c66d; 0xb00327c8; 0xbf597fc7; 0xc6e00bf3; 0xd5a79147; 0x06ca6351; 0x14292967;
  0x27b70a85; 0x2e1b2138; 0x4d2c6dfc; 0x53380d13; 0x650a7354; 0x766a0abb; 0x81c2c92e; 0x92722c85;
  0xa2bfe8a1; 0xa81a664b; 0xc24b8b70; 0xc76c51a3; 0xd192e819; 0xd6990624; 0xf40e3585; 0x106aa070;
  0x19a4c116; 0x1e376c08; 0x2748774c; 0x34b0bcb5; 0x391c0cb3; 0x4ed8aa4a; 0x5b9cca4f; 0x682e6ff3;
  0x748f82ee; 0x78a5636f; 0x84c87814; 0x8cc70208; 0x90befffa; 0xa4506ceb; 0xbef9a3f7; 0xc67178f2 |]

let sha256 (msg : Bytes.t) : Bytes.t =
  let m32 x = x land 0xFFFFFFFF in
  let rotr x n = m32 ((x lsr n) lor (x lsl (32 - n))) in
  let len = Bytes.length msg in
  let padded_len = ((len + 8) / 64 + 1) * 64 in
  let p = Bytes.make padded_len '\000' in
  Bytes.blit msg 0 p 0 len;
  Bytes.set p len '\x80';
  let bits = len * 8 in
  for i = 0 to 7 do
    Bytes.set p (padded_len - 1 - i) (Char.chr ((bits lsr (8 * i)) land 0xFF))
  done;
  let h = [| 0x6a09e667; 0xbb67ae85; 0x3c6ef372; 0xa54ff53a;
             0x510e527f; 0x9b05688c; 0x1f83d9ab; 0x5be0cd19 |] in
  let w = Array.make 64 0 in
  for blk = 0 to padded_len / 64 - 1 do
    let off = blk * 64 in
    for i = 0 to 15 do
      let b j = Char.code (Bytes.get p (off + 4 * i + j)) in
      w.(i) <- (b 0 lsl 24) lor (b 1 lsl 16) lor (b 2 lsl 8) lor b 3
    done;
    for i = 16 to 63 do
      let s0 = rotr w.(i-15) 7 lxor rotr w.(i-15) 18 lxor (w.(i-15) lsr 3) in
      let s1 = rotr w.(i-2) 17 lxor rotr w.(i-2) 19 lxor (w.(i-2) lsr 10) in
      w.(i) <- m32 (w.(i-16) + s0 + w.(i-7) + s1)
    done;
    let a = ref h.(0) and b = ref h.(1) and c = ref h.(2) and d = ref h.(3)
    and e = ref h.(4) and f = ref h.(5) and g = ref h.(6) and hh = ref h.(7) in
    for i = 0 to 63 do
      let s1 = rotr !e 6 lxor rotr !e 11 lxor rotr !e 25 in
      let ch = (!e land !f) lxor (m32 (lnot !e) land !g) in
      let t1 = m32 (!hh + s1 + ch + sha256_k.(i) + w.(i)) in
      let s0 = rotr !a 2 lxor rotr !a 13 lxor rotr !a 22 in
      let maj = (!a land !b) lxor (!a land !c) lxor (!b land !c) in
      let t2 = m32 (s0 + maj) in
      hh := !g; g := !f; f := !e; e := m32 (!d + t1);
      d := !c; c := !b; b := !a; a := m32 (t1 + t2)
    done;
    h.(0) <- m32 (h.(0) + !a); h.(1) <- m32 (h.(1) + !b);
    h.(2) <- m32 (h.(2) + !c); h.(3) <- m32 (h.(3) + !d);
    h.(4) <- m32 (h.(4) + !e); h.(5) <- m32 (h.(5) + !f);
    h.(6) <- m32 (h.(6) + !g); h.(7) <- m32 (h.(7) + !hh)
  done;
  let out = Bytes.create 32 in
  Array.iteri (fun i x ->
    for j = 0 to 3 do
      Bytes.set out (4 * i + j) (Char.chr ((x lsr (24 - 8 * j)) land 0xFF))
    done) h;
  out

(* HMAC-SHA256 (RFC 2104) *)
let hmac_sha256 key msg =
  let key = if Bytes.length key > 64 then sha256 key else key in
  let k = Bytes.make 64 '\000' in
  Bytes.blit key 0 k 0 (Bytes.length key);
  let pad c = Bytes.map (fun x -> Char.chr (Char.code x lxor c)) k in
  sha256 (Bytes.cat (pad 0x5c) (sha256 (Bytes.cat (pad 0x36) msg)))

let verify cert key_id max_wcet max_budget max_agents max_leakage stored_epoch mac_key =
  let mac_ok = Bytes.equal (hmac_sha256 mac_key (Bytes.sub cert 0 0x1E0)) (Bytes.sub cert 0x1E0 32) in
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
  let epoch_ok = u64_lt stored_epoch epoch in

  mac_ok && key_ok && wcet_ok && budget_ok && agents_ok && leakage_ok && epoch_ok

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
  if Array.length Sys.argv <> 9 then (
    eprintf "Usage: %s <cert_path> <key_id_hex> <max_wcet_ns> <max_budget> <max_agents> <max_leakage> <stored_epoch> <mac_key_hex>\n" Sys.argv.(0);
    exit 2
  );
  let cert_path = Sys.argv.(1) in
  let key_id_hex = Sys.argv.(2) in
  let max_wcet = u64_of_string Sys.argv.(3) in
  let max_budget = u64_of_string Sys.argv.(4) in
  let max_agents = u8_of_string Sys.argv.(5) in
  let max_leakage = u8_of_string Sys.argv.(6) in
  let stored_epoch = u64_of_string Sys.argv.(7) in
  let mac_key = hex_to_bytes Sys.argv.(8) in

  let key_id = hex_to_bytes key_id_hex in
  let ic = open_in_bin cert_path in
  let cert = Bytes.create 512 in
  really_input ic cert 0 512;
  close_in ic;

  if verify cert key_id max_wcet max_budget max_agents max_leakage stored_epoch mac_key then (
    printf "VERIFIED\n";
    exit 0
  ) else (
    printf "REJECTED\n";
    exit 1
  )
