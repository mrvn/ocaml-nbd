let port = 10809

let servers = Hashtbl.create 0

let abort server reason =
  let fd = server.Nbd.Handshake.Server.con.Nbd.IO.fd
  in
  Unix.close fd;
  Hashtbl.remove servers fd;
  Printf.printf "Aborting connection: %s\n" reason

let export_name server name =
  Printf.printf "starting nbd for %s\n" name;
  abort server "(not doing export_name)"

let list server = [("export1", ""); ("export2", "test export")]
  
let negotiator = {
  Nbd.Handshake.Server.export_name = export_name;
  Nbd.Handshake.Server.abort = abort;
  Nbd.Handshake.Server.list = list;
}

let rec loop listener =
  let rdfds = listener ::
    (Hashtbl.fold
       (fun _ s acc -> s.Nbd.Handshake.Server.con.Nbd.IO.fd :: acc)
       servers
       [])
  in
  let wrfds =
    Hashtbl.fold
      (fun _ s acc ->
	let con = s.Nbd.Handshake.Server.con
	in
	if Nbd.IO.needs_write con
	then con.Nbd.IO.fd :: acc
	else acc)
      servers
      []
  in
  Printf.printf "select\n";
  flush_all ();
  let (rdfds, wrfds, _) = Unix.select rdfds wrfds [] (-.1.0)
  in
  List.iter
    (fun fd ->
      Printf.printf "can write\n";
      flush_all ();
      let server = Hashtbl.find servers fd
      in
      try
	Nbd.IO.do_write server.Nbd.Handshake.Server.con
      with Unix.Unix_error (error, s1, s2) ->
	abort server (Unix.error_message error))
    wrfds;
  List.iter
    (fun fd ->
      Printf.printf "can read\n";
      flush_all ();
      if fd = listener
      then      
	let (fd, _) = Unix.accept fd in
	Printf.printf "accepting new client\n";
	flush_all ();
	let server = Nbd.Handshake.Server.make fd negotiator
	in
	Unix.set_nonblock fd;
	Hashtbl.add servers fd server
      else
	let server = Hashtbl.find servers fd
	in
	try
	  Nbd.IO.do_read server.Nbd.Handshake.Server.con
	with
	| Unix.Unix_error (error, s1, s2) ->
	    abort server (Unix.error_message error)
	| End_of_file ->
	  abort server "connection closed by peer")
      rdfds;
  loop listener

let _ =
  Printf.printf "NBD-server V0.0.0\n";
  flush_all ();
  let listener =
    Unix.socket
      Unix.PF_INET
      Unix.SOCK_STREAM
      0
  in
  Unix.setsockopt listener Unix.SO_REUSEADDR true;
  Unix.setsockopt_optint listener Unix.SO_LINGER (Some 10);
  Unix.bind listener (Unix.ADDR_INET (Unix.inet_addr_any, port));
  Unix.listen listener 100;
  Unix.set_nonblock listener;
  loop listener
