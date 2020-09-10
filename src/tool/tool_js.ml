(**************************************************************************)
(*                                BELENIOS                                *)
(*                                                                        *)
(*  Copyright © 2012-2020 Inria                                           *)
(*                                                                        *)
(*  This program is free software: you can redistribute it and/or modify  *)
(*  it under the terms of the GNU Affero General Public License as        *)
(*  published by the Free Software Foundation, either version 3 of the    *)
(*  License, or (at your option) any later version, with the additional   *)
(*  exemption that compiling, linking, and/or using OpenSSL is allowed.   *)
(*                                                                        *)
(*  This program is distributed in the hope that it will be useful, but   *)
(*  WITHOUT ANY WARRANTY; without even the implied warranty of            *)
(*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU     *)
(*  Affero General Public License for more details.                       *)
(*                                                                        *)
(*  You should have received a copy of the GNU Affero General Public      *)
(*  License along with this program.  If not, see                         *)
(*  <http://www.gnu.org/licenses/>.                                       *)
(**************************************************************************)

open Js_of_ocaml
open Belenios_platform
open Belenios
open Belenios_tool_common
open Platform
open Serializable_j
open Tool_js_common

let install_handler (id, handler) =
  let f _ =
    begin try handler () with e ->
      let msg = "Unexpected error: " ^ Printexc.to_string e in
      alert msg
    end;
    Js._false
  in
  Js.Opt.iter
    (document##getElementById (Js.string id))
    (fun e -> e##.onclick := Dom_html.handler f)

module Tests = struct

  let unit_tests () =
    let a = "13133254971699857128" and b = "31748915560162976106" in
    let c = Z.of_string a and d = Z.of_string b in
    let ntests = ref 0 in
    let check name f =
      if not (f ()) then Printf.ksprintf failwith "test %s failed" name;
      incr ntests
    in
    check "ZERO" (fun () -> Z.to_string Z.zero = "0");
    check "ONE" (fun () -> Z.to_string Z.one = "1");
    let string_roundtrip a c () = a = Z.to_string c in
    check "string_roundtrip_a" (string_roundtrip a c);
    check "string_roundtrip_b" (string_roundtrip b d);
    let operator op expected () = expected = Z.to_string (op c d) in
    check "add" (operator Z.( + ) "44882170531862833234");
    check "mul" (operator Z.( * ) "416966603126589360375328894595477783568");
    check "sub" (operator Z.( - ) "-18615660588463118978");
    let a = 132180439 and b = 41907500 in
    let c = Z.of_int a and d = Z.of_int b in
    let int_roundtrip a c () = a = Z.to_int c in
    check "int_roundtrip_a" (int_roundtrip a c);
    check "int_roundtrip_b" (int_roundtrip b d);
    let m = Z.of_int 181944121 in
    check "mod" (fun () -> Z.to_int Z.((c * d) mod m) = 30881634);
    check "erem" (fun () -> Z.to_int Z.(erem (zero - c * d) m) = 151062487);
    check "powm" (fun () -> Z.to_int (Z.powm c d m) = 81171525);
    check "invert" (fun () -> Z.to_int (Z.invert c m) = 54455411);
    check "prime" (fun () -> Z.probab_prime m 5 > 0);
    check "eq" (fun () -> Z.(c =% c));
    check "neq" (fun () -> Z.(not (c =% d)));
    check "geq" (fun () -> Z.compare c d >= 0);
    check "lt" (fun () -> Z.compare d c < 0);
    let i = Z.of_string "272660753928370030481696309961224617984" in
    check "bit_length" (fun () -> Z.bit_length i = 128);
    let j = Z.of_bits "\x81\xab\xd3\xed\x0b\x19\x2e\x40\x7a\xca" in
    let k = Z.of_string "956173156978067279948673" in
    check "of_bits" (fun () -> Z.(j =% k));
    let key = "0000000000000000000000000000000000000000000000000000000000000000" in
    let iv = "00000000000000000000000000000000" in
    check "AES" (fun () -> aes_hex ~key ~data:iv = "dc95c078a2408989ad48a21492842087");
    let plaintext = "Lorem ipsum dolor sit amet, consectetur adipiscing elit." in
    let ciphertext = "91f136cd65db6fa83b4943395e388089d4a8d0531b43a24a6498a1433559039ce5a18734752e13418718be1c2da5cca3d89e6e62fb729a81ec1cb3d1174e770c" in
    check "AES-CCM-encrypt" (fun () -> encrypt ~key ~iv ~plaintext = ciphertext);
    check "AES-CCM-decrypt" (fun () -> decrypt ~key ~iv ~ciphertext = plaintext);
    Printf.ksprintf alert "%d tests were successful!" !ntests

  let bench_powm () =
    let n = 100 in
    let a = Z.of_string "30853945840174597120626721846450126314606685045265314267738848011863412997744965327336348477924933167005834532279700438305205349395799555380298036421360430773460934119892692300142378546873667179079814466491492611759008787000622911850181117319179885358518118087002567200494558111372663472816700979626698342136091679008920714916697606979211099532626875131128698361120616072546047452123223884113018200823661347210982961457277048742341447670150939858292248553304276963050079119868152424939371279866285547894450497179332713959439322280562800964537259975022546560313279576398606921294360105203419399168177202864123326706057" in
    let b = Z.of_string "14819939028953781742828614102646561767503175195767893300754792157264784353156516390124979555585996023489169949126621747230243670356270820011579970610574477122782323554808537054373243587469800532780586920093499586498630387766110427230278269993001982734422697704386244907459536870293258944887480320668921711004376689265489289358917367072320310010159231121859887203513856330972371464518400704528743841045232559484451944478789199135455911802951204157526268950262470405753241413631071106235874367101847758053982230081762103923406326223085485533921832052842253002365731936871982755922663988441352675836760402401740328212260" in
    let p = Z.of_string "32317006071311007300338913926423828248817941241140239112842009751400741706634354222619689417363569347117901737909704191754605873209195028853758986185622153212175412514901774520270235796078236248884246189477587641105928646099411723245426622522193230540919037680524235519125679715870117001058055877651038861847280257976054903569732561526167081339361799541336476559160368317896729073178384589680639671900977202194168647225871031411336429319536193471636533209717077448227988588565369208645296636077250268955505928362751121174096972998068410554359584866583291642136218231078990999448652468262416972035911852507045361090559" in
    let start = new%js Js.date_now in
    for _ = 1 to n do ignore (Z.powm a b p) done;
    let stop = new%js Js.date_now in
    let delta = int_of_float (ceil (stop##valueOf -. start##valueOf)) in
    Printf.ksprintf alert "%d modular exponentiations in %d ms!" n delta

  let cmds =
    [
      "do_unit_tests", unit_tests;
      "bench_powm", bench_powm;
    ]
end

module Tkeygen = struct
  open Tool_tkeygen

  let tkeygen () =
    let module P : PARAMS = struct
      let group = get_textarea "election_group"
    end in
    let module X = (val make (module P : PARAMS) : S) in
    let open X in
    let {id; priv; pub} = trustee_keygen () in
    set_textarea "tkeygen_id" id;
    set_textarea "tkeygen_secret" priv;
    set_textarea "tkeygen_public" pub

  let cmds = ["do_tkeygen", tkeygen]
end

let split_lines str =
  let str = str ^ "\n" in
  let n = String.length str in
  let rec loop accu i =
    if i < n
    then (
      let j = String.index_from str i '\n' in
      let line = String.sub str i (j-i) in
      let accu = if line = "" then accu else line :: accu in
      loop accu (j+1)
    ) else List.rev accu
  in loop [] 0

module Credgen = struct
  open Tool_credgen

  let derive () =
    let module P : PARAMS = struct
      let uuid = get_textarea "election_uuid"
      let group = get_textarea "election_group"
    end in
    let module X = (val make (module P : PARAMS) : S) in
    let cred = get_textarea "credgen_derive_input" in
    set_textarea "credgen_derive_output" (X.derive cred)

  let generate ids =
    let module P : PARAMS = struct
      let uuid = get_textarea "election_uuid"
      let group = get_textarea "election_group"
    end in
    let module X = (val make (module P : PARAMS) : S) in
    let privs, pubs = X.generate ids in
    let privs =
      List.combine ids privs
      |> List.map (fun (id, priv) -> id ^ " " ^ priv)
    in
    set_textarea "credgen_generated_creds"
      (privs |> String.concat "\n");
    set_textarea "credgen_generated_pks"
      (pubs |> String.concat "\n")

  let generate_n () =
    get_textarea "credgen_number" |>
    int_of_string |> generate_ids |> generate

  let generate_ids () =
    get_textarea "credgen_ids" ^ "\n" |>
    split_lines |> generate

  let cmds = [
    "do_credgen_derive", derive;
    "do_credgen_generate", generate_n;
    "do_credgen_ids", generate_ids;
  ]
end

module Mkelection = struct
  open Tool_mkelection

  let mkelection () =
    let module P : PARAMS = struct
      let uuid = get_textarea "election_uuid"
      let group = get_textarea "election_group"
      let template = get_textarea "mkelection_template"
      let get_trustees () =
        get_textarea "mkelection_pks"
        |> split_lines
        |> List.map (trustee_public_key_of_string Yojson.Safe.read_json)
        |> List.map (fun x -> `Single x)
        |> string_of_trustees Yojson.Safe.write_json
    end in
    let module X = (val make (module P : PARAMS) : S) in
    set_textarea "mkelection_output" (X.mkelection ())

  let cmds = [
    "do_mkelection", mkelection;
  ]
end

module ToolElection = struct
  open Tool_election

  module Getters = struct

    let get_public_keys () =
      let pks = get_textarea "election_pks" |> split_lines in
      if pks = [] then None else Some pks

    let get_trustees () =
      get_public_keys ()
      |> Option.map
           (fun x ->
             x
             |> List.map (trustee_public_key_of_string Yojson.Safe.read_json)
             |> List.map (fun x -> `Single x)
             |> string_of_trustees Yojson.Safe.write_json
           )

    let get_public_creds () =
      let raw = get_textarea "election_pubcreds" |> split_lines in
      match raw with
      | [] -> None
      | _ -> Some (Stream.of_list raw)

    let get_ballots () =
      let raw = get_textarea "election_ballots" |> split_lines in
      match raw with
      | [] -> None
      | _ -> Some (Stream.of_list raw)

    let get_result () =
      let raw = get_textarea "election_result" |> split_lines in
      match raw with
      | [] -> None
      | [r] -> Some r
      | _ -> invalid_arg "invalid result"

    let get_shuffles () =
      None

    let print_msg x = alert x
  end

  let get_election () =
    let raw = get_textarea "election_params" in
    match split_lines raw with
    | [e] -> e
    | _ -> invalid_arg "invalid election parameters"


  let create_ballot () =
    let module P : PARAMS = struct
      let election = get_election ()
      include Getters
    end in
    let choices = get_textarea "election_choices" |> plaintext_of_string in
    let privcred = get_textarea "election_privcred" in
    let module X = (val make (module P : PARAMS) : S) in
    set_textarea "election_ballot" (X.vote (Some privcred) choices)

  let verify () =
    let module P : PARAMS = struct
      let election = get_election ()
      include Getters
    end in
    let module X = (val make (module P : PARAMS) : S) in
    X.verify ()

  let decrypt () =
    let module P : PARAMS = struct
      let election = get_election ()
      include Getters
    end in
    let module X = (val make (module P : PARAMS) : S) in
    let privkey = get_textarea "election_privkey" in
    set_textarea "election_pd" (X.decrypt privkey)

  let validate () =
    let module P : PARAMS = struct
      let election = get_election ()
      include Getters
    end in
    let module X = (val make (module P : PARAMS) : S) in
    let factors = get_textarea "election_factors" |> split_lines in
    set_textarea "election_result" (X.validate factors)

  let cmds = [
    "do_encrypt", create_ballot;
    "do_verify", verify;
    "do_decrypt", decrypt;
    "do_validate", validate;
  ]

end

let int_of_quad str =
  let ( ! ) x = int_of_char str.[x] in
  (((((!0 lsl 8) lor !1) lsl 8) lor !2) lsl 8) lor !3

let new_uuid () =
  let seed = Array.init 16 (fun _ ->
    random_string secure_rng 4 |> int_of_quad
  ) in
  let s = Random.State.make seed in
  let uuid = Uuidm.v4_gen s () in
  set_textarea "election_uuid" (Uuidm.to_string uuid)

let cmds =
  ["new_uuid", new_uuid] @
  Tests.cmds @
  Tkeygen.cmds @
  Credgen.cmds @
  Mkelection.cmds @
  ToolElection.cmds

let install_handlers () =
  List.iter install_handler cmds

let () =
  Dom_html.window##.onload := Dom_html.handler (fun _ ->
    install_handlers ();
    Js._false
  )
