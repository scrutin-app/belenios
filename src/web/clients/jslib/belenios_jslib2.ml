(* you may have to do this to require this file on nodejs *)
(* belenios = {}; navigator = {userAgent: ""} *)

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

let make_election () : 'a = 
  let questions = [] in

  let template : template = {
    t_description = "Test election";
    t_name = "Test election";
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

let belenios =
  object%js
    method print =
      print_endline("Coucou")
    method generate_trustee_key () =
      generate_trustee_key ()
    method make_election () = make_election ()
  end

let () = Js.export "belenios" belenios
