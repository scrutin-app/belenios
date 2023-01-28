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

let generate_trustees () =
  Belenios_tool_common.Tool_tkeygen.(
    let module R = Make (P) (Random) () in
    let kp = R.trustee_keygen () in
    (*kp.R.id, kp.R.pub, kp.R.priv*)
    let my_trustee_key = trustee_public_key_of_string Yojson.Safe.read_json kp.R.pub in
    (*kp.R.pub*)
    let my_trustee : 'a Serializable_t.trustee_kind = `Single(my_trustee_key) in
    kp.R.priv, [my_trustee]  
  )

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

  let priv, trustees_tmp = generate_trustees () in
  let trustees = string_of_trustees Yojson.Safe.write_json trustees_tmp in
  print_endline trustees;

  let module P = struct
    let version = 1
    let group = "BELENIOS-2048"
    let uuid = generate_token ()
    let template = template |> string_of_template
    let get_trustees () = trustees
  end in

  Belenios_tool_common.Tool_mkelection.(
    let module R = (val make (module P : PARAMS) : S) in
    let params = R.mkelection () in
    priv, trustees, params
  )

let make_credentials uuid n =
  let module P = struct
    let version = 1
    let group = "BELENIOS-2048"
    let uuid = uuid
  end in
  Belenios_tool_common.Tool_credgen.(
    let module R = Make (P) (Random) () in
    let ids = generate_ids n in
    R.generate ids
  )

module type ELECTION_LWT = ELECTION with type 'a m = 'a Lwt.t

let encrypt_ballot election cred plaintext trustees =
  Belenios_tool_common.Tool_election.(
    let module PR : PARAMS_RAW = struct
      let raw_election = election
      let trustees = trustees
      let ballots = []
      let public_creds = []
      let pds = []
    end in
    let module X = MakeRaw (PR) () in
    X.vote (Some cred) plaintext
  )

let compute_encrypted_tally election ballots trustees public_creds =
  Belenios_tool_common.Tool_election.(
    let module PR : PARAMS_RAW = struct
      let raw_election = election
      let trustees = trustees
      let ballots = ballots
      let public_creds = public_creds
      let pds = []
    end in
    let module X = MakeRaw (PR) () in
    X.compute_encrypted_tally ()
  )

let decrypt election ballots trustees public_creds priv_key =
  Belenios_tool_common.Tool_election.(
    let module PR : PARAMS_RAW = struct
      let raw_election = election
      let trustees = trustees
      let ballots = ballots
      let public_creds = public_creds
      let pds = []
    end in
    let module X = MakeRaw (PR) () in
    X.decrypt 1 priv_key
  )

let compute_result election ballots trustees public_creds partial_decryptions = 
  Belenios_tool_common.Tool_election.(
    let module PR : PARAMS_RAW = struct
      let raw_election = election
      let trustees = trustees
      let ballots = ballots
      let public_creds = public_creds
      let pds = partial_decryptions
    end in
    let module X = MakeRaw (PR) () in
    X.compute_result ()
  )

let ballotTracker ballot = 
  sha256_b64 ballot

let belenios =
  object%js
    method makeElection (name:Js.js_string Js.t) (description:Js.js_string Js.t) (js_options:(Js.js_string Js.t) Js.js_array Js.t) =
      let options_tmp = js_options |> Js.to_array in
      let options : string array = Array.map Js.to_string options_tmp in
      let priv, trustees, election = make_election (Js.to_string name) (Js.to_string description) options in
      election |> Js.string

    method encryptBallot (election:Js.js_string Js.t) (cred:Js.js_string Js.t) (plaintext:(int Js.js_array Js.t) Js.js_array Js.t) (trustees:Js.js_string Js.t) =
      encrypt_ballot (Js.to_string election) (Js.to_string cred) (Array.map Js.to_array (Js.to_array plaintext)) (Js.to_string trustees)
    
    method makeCredentials (uuid:Js.js_string Js.t) (n:int) =
      ()

    method demo () =
      let priv, trustees, election = make_election "test" "test" [| "fraise"; "framboise" |] in

      let election_struct = params_of_string election in
      let uuid_s = (string_of_uuid election_struct.e_uuid) in
      let uuid = String.sub uuid_s 1 ((String.length uuid_s) - 2) in

      let credentials = make_credentials uuid 10 in
      let public_creds = credentials.public in 
      let private_creds = credentials.priv in 

      let get_snd (a, b) = b in
      let get_priv_n l n = get_snd (List.nth l n) in
      
      let ballot_1 = encrypt_ballot election (get_priv_n private_creds 0) [| [|0; 1|] |] trustees in
      let ballot_2 = encrypt_ballot election (get_priv_n private_creds 1) [| [|0; 1|] |] trustees in
      let ballot_3 = encrypt_ballot election (get_priv_n private_creds 2) [| [|1; 0|] |] trustees in

      let a, b = compute_encrypted_tally election [ballot_1; ballot_2; ballot_3] trustees public_creds in
      print_endline a;
      print_endline b;

      let a, b = decrypt election [ballot_1; ballot_2; ballot_3] trustees public_creds priv in
      print_endline a;
      print_endline b;

      let my_owned_hash = owned_of_string read_hash b in
      let partial_decryptions = [
        (my_owned_hash.owned_payload,my_owned_hash,a)
      ] in

      let res = compute_result election [ballot_1; ballot_2; ballot_3] trustees public_creds partial_decryptions in
      print_endline res;
      ()
  end

let () = Js.export "belenios" belenios