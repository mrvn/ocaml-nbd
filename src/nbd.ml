module EU = ExtUnix.Specific

module IO = struct
  type 'a t = {
    fd : Unix.file_descr;
    mutable out_queue : EU.buffer Queue.t;
    mutable buf_in: EU.buffer;
    mutable buf_pos: EU.buffer;
    mutable parse: 'a t -> EU.buffer -> unit;
    mutable data : 'a;
  }

  let make fd len parse data =
    let buf = EU.memalign 8 len
    in
    {
      fd = fd;
      out_queue = Queue.create ();
      buf_in = buf;
      buf_pos = buf;
      parse = parse;
      data = data;
    }
    
  let needs_write t = not (Queue.is_empty t.out_queue)
    
  let write t buf =
    if needs_write t
    then Queue.add buf t.out_queue
    else
      let len = EU.BA.write t.fd buf in
      let len2 = Bigarray.Array1.dim buf
      in
      Printf.printf "wrote %d/%d bytes\n" len len2;
      flush_all ();
      if len < len2
      then Queue.add (Bigarray.Array1.sub buf len (len2 - len)) t.out_queue

  let rec do_write t =
    if needs_write t
    then
      let buf = Queue.take t.out_queue in
      let len =
	try
	  EU.BA.write t.fd buf
	with Unix.Unix_error (error, s1, s2) as exn ->
	  if (error = Unix.EAGAIN) || (error = Unix.EWOULDBLOCK)
	  then 0
	  else raise exn  
      in
      let len2 = Bigarray.Array1.dim buf
      in
      Printf.printf "wrote %d/%d bytes\n" len len2;
      flush_all ();
      if len = len2
      then do_write t
      else
	let q = Queue.create () in
	let buf = Bigarray.Array1.sub buf len (len2 - len)
	in
	Queue.add buf q;
	Queue.transfer t.out_queue q;
	t.out_queue <- q

  let do_read t =
    let len2 = Bigarray.Array1.dim t.buf_pos
    in
    try
      let len = EU.BA.read t.fd t.buf_pos
      in
      Printf.printf "read %d/%d bytes\n" len len2;
      flush_all ();
      if len = 0
      then raise End_of_file;
      if len = len2
      then t.parse t t.buf_in
      else t.buf_pos <- Bigarray.Array1.sub t.buf_pos len (len2 - len)
    with Unix.Unix_error (error, s1, s2) as exn ->
      if (error = Unix.EAGAIN) || (error = Unix.EWOULDBLOCK)
      then begin
	Printf.printf "read 0/%d bytes\n" len2;
	flush_all ();
      end
      else raise exn

  let read t len ?(now = false) parse =
    let buf = EU.memalign 8 len
    in
    t.buf_in <- buf;
    t.buf_pos <- buf;
    t.parse <- parse;
    if now
    then do_read t
end
  
module Handshake = struct
  let opt_magic = "IHAVEOPT" (* 0x49484156454F5054 *)
  let reply_magic = 0x3e889045565a9L

  let server_hello =
    "NBDMAGIC"
    ^ opt_magic (* 0x49484156454F5054 *)
    ^ "\000\001" (* 16bit flags: fixed new style *)

  let client_fixed_newstyle = Int32.one

  let rep_ack          = Int32.one                  (* 1 *)
  let rep_server       = Int32.succ rep_ack         (* 2 *)
  let rep_flag_error   = Int32.min_int              (* 0x80000000 *)
  let rep_err_unsup    = Int32.succ rep_flag_error  (* 0x80000001 *)
  let rep_err_policy   = Int32.succ rep_err_unsup   (* 0x80000002 *)
  let rep_err_invalid  = Int32.succ rep_err_policy  (* 0x80000003 *)
  let rep_err_platform = Int32.succ rep_err_invalid (* 0x80000004 *)

  let max_buf_size = 4096
  let req_size = 16

  module Server = struct
    type negotiator = {
      export_name : t -> string -> unit;
      abort : t -> string -> unit;
      list : t -> (string * string) list;
    }
    and t = {
      con: t IO.t;
      ops : negotiator;
    }

    exception Negotiation_Complete

    let reply server opt code len =
      let buf = EU.memalign 8 20
      in
      EU.BA.BigEndian.unsafe_set_int64 buf 0 reply_magic;
      EU.BA.BigEndian.unsafe_set_uint31 buf 8 opt;
      EU.BA.BigEndian.unsafe_set_int32 buf 12 code;
      EU.BA.BigEndian.unsafe_set_uint31 buf 16 len;
      IO.write server.con buf

    let reply_no_data server opt code =
      reply server opt code 0

    let reply_data server opt code data =
      reply server opt code (Bigarray.Array1.dim data);
      IO.write server.con data
      
    let reply_server server opt name descr =
      let len_name = String.length name in
      let len_descr = String.length descr in
      let buf = EU.memalign 8 (4 + len_name + len_descr)
      in
      EU.BA.BigEndian.unsafe_set_uint31 buf 0 len_name;
      EU.BA.unsafe_set_substr buf 4 name;
      EU.BA.unsafe_set_substr buf (4 + len_name) descr;
      reply_data server opt rep_server buf

    let never_call _ = raise Negotiation_Complete

    let rec handle_option opt optdata server =
      Printf.printf "handle_option\n";
      flush_all ();
      match opt with
      | 1 -> (* export name *)
	begin
	  Printf.printf "export name\n";
	  flush_all ();
	  IO.read server.con 1 never_call;
	  match optdata with
	  | None -> reply_no_data server opt rep_err_invalid
	  | Some data ->
	    let name =
	      EU.BA.unsafe_get_substr data 0 (Bigarray.Array1.dim data)
	    in
	    server.ops.export_name server name
	end
      | 2 -> (* abort *)
	begin
	  Printf.printf "abort\n";
	  flush_all ();
	  IO.read server.con 1 never_call;
	  match optdata with
	  | None -> server.ops.abort server "client request"
	  | Some data -> reply_no_data server opt rep_err_invalid
	end
      | 3 -> (* list *)
	begin
	  Printf.printf "list\n";
	  flush_all ();
	  IO.read server.con req_size parse_option;
	  match optdata with
	  | None ->
	    let exports = server.ops.list server
	    in
	    List.iter
	      (fun (name, descr) -> reply_server server opt name descr)
	      exports;
	    reply_no_data server opt rep_ack
	  | Some data -> reply_no_data server opt rep_err_invalid
	end
      | _ -> (* unknown option *)
	Printf.printf "unknown\n";
	flush_all ();
	IO.read server.con req_size parse_option;
	reply_no_data server opt rep_err_unsup
    and parse_option_data opt con buf =
      Printf.printf "parse_option_data\n";
      flush_all ();
      handle_option opt (Some buf) con.IO.data
    and parse_option con buf =
      Printf.printf "parse_option\n";
      flush_all ();
      let magic = EU.BA.unsafe_get_substr buf 0 8
      in
      if magic = opt_magic
      then
	let opt = EU.BA.BigEndian.unsafe_get_uint31 buf 8 in
	let len = EU.BA.BigEndian.unsafe_get_uint31 buf 12
	in
	if len > 0
	then IO.read con len ~now:true (parse_option_data opt)
	else handle_option opt None con.IO.data
      else con.IO.data.ops.abort con.IO.data "magic mismatch"

    let parse_hello con buf =
      Printf.printf "parse_hello\n";
      flush_all ();
      (* still saying hello *)
      let flags = EU.BA.BigEndian.unsafe_get_int32 buf 0
      in
      if flags = client_fixed_newstyle
      then (* start recieving options *)
	IO.read con req_size parse_option
      else
	con.IO.data.ops.abort con.IO.data "protocol mismatch"
	  
    let make fd negotiator =
      let con = IO.make fd 4 parse_hello (Obj.magic 0)
      in
      let server =
	{
	  con = con;
	  ops = negotiator;
	}
      in
      con.IO.data <- server;
      let buf = EU.memalign 8 18
      in
      EU.BA.unsafe_set_substr buf 0 server_hello;
      IO.write server.con buf;
      server
  end
(*
  module Client = struct
    type t = {
      con : connection;
      mutable said_hello : bool;
    }
    
    let make fd =
      let buf = EU.memalign 8 4 in
      let con = {
	fd = fd;
	buf_out = Queue.create ();
	buf_in = buf;
	need_pos = buf;
	need_in = 0;
      } in
      EU.BA.BigEndian.unsafe_set_int32 buf 0 client_fixed_newstyle;
      Queue.add buf con.buf_out;
      set_needed con 18;
      {
	con = con;
	said_hello = false;
      }
  end
*)
end
