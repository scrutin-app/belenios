(* you may have to do this to require this file on nodejs *)
(* belenios = {}; navigator = {userAgent: ""} *)

[@@@ocaml.warning "-26-27-32-33-35-39"]

open Lwt.Syntax
open Js_of_ocaml
open Js_of_ocaml_lwt
open Belenios_core.Common
open Belenios_core
open Belenios
open Signatures
open Serializable_j
open Belenios_js.Common

module P = struct
  let group = "BELENIOS-2048"
  let version = 1
end

open Belenios_platform.Platform

module Random = struct
  type 'a t = 'a
  let yield () = ()
  let return x = x
  let bind x f = f x
  let fail e = raise e

  let prng = lazy (pseudo_rng (random_string secure_rng 16))

  let random q =
    let size = bytes_to_sample q in
    let r = random_string (Lazy.force prng) size in
    Z.(of_bits r mod q)
end

let generate_token () =
  let module X = MakeGenerateToken (Random) in
  X.generate_token ~length:14 ()

let generate_trustee_key () : 'a trustee_public_key =
  Belenios_tool_common.Tool_tkeygen.(
    let module R = Make (P) (Random) () in
    let kp = R.trustee_keygen () in
    (*kp.R.id, kp.R.pub, kp.R.priv*)
    trustee_public_key_of_string Yojson.Safe.read_json kp.R.pub
    (*kp.R.pub*)
  )

let generate_trustees () : 'a trustees =
  let my_trustee_key = generate_trustee_key () in
  let my_trustee : 'a Serializable_t.trustee_kind = `Single(my_trustee_key) in
  [my_trustee]

let make_election (name:string) (description:string) (options:string array) : 'a = 

  let questions : question list = 
    let question_body: Question_h_t.question = {
      q_answers = options;
      q_blank = Some(false);
      q_min = 0;
      q_max = 1;
      q_question = "Best";
    } in
    let question : question = Homomorphic(question_body) in
    [
      question
    ]
  in

  let template : template = {
    t_name = name;
    t_description = description;
    t_questions = Array.of_list(questions);
    t_administrator = None;
    t_credential_authority = None;
  } in

  let module P = struct
    let version = 1
    let group = "BELENIOS-2048"
    let uuid = generate_token ()
    let template = template |> string_of_template
    let get_trustees () = string_of_trustees Yojson.Safe.write_json (generate_trustees ())
  end in

  Belenios_tool_common.Tool_mkelection.(
    let module R = (val make (module P : PARAMS) : S) in
    let params = R.mkelection () in
    params
  )

module type ELECTION_LWT = ELECTION with type 'a m = 'a Lwt.t

let encryptBallot election cred plaintext =
  let module R = struct let raw_election = election end in
  let module P = Election.Make (R) (Random) () in
  let module CD = Credential.MakeDerive (P.G) in
  (* let module P = (val election : ELECTION_LWT) in *)
  (* let module G = P.G in *)
  (* let module CD = Credential.MakeDerive (G) in *)
  let sk = CD.derive P.election.e_uuid cred in
  let b = P.E.create_ballot ~sk plaintext in
  let ballot = P.string_of_ballot b in
  ballot

(*
let decrypt election cred plaintext =
  let module RAW_ELECTION = struct let raw_election = election end in
  let module ELECTION = Election.Make (RAW_ELECTION) (Random) () in
*)

let ballotTracker ballot = 
  sha256_b64 ballot

let belenios =
  object%js
    method makeElection (name:Js.js_string Js.t) (description:Js.js_string Js.t) (js_options:(Js.js_string Js.t) Js.js_array Js.t) =
      let options_tmp = js_options |> Js.to_array in
      let options : string array = Array.map Js.to_string options_tmp in
      let election = make_election (Js.to_string name) (Js.to_string description) options in
      election |> Js.string
    method encryptBallot election (cred:Js.js_string Js.t) (plaintext:(int Js.js_array Js.t) Js.js_array Js.t) =
      encryptBallot (Js.to_string election) (Js.to_string cred) (Array.map Js.to_array (Js.to_array plaintext))
  end

let () = Js.export "belenios" belenios
