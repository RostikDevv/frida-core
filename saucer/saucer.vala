namespace Frida.Saucer {
	private static Application application;

	private const string DEFAULT_LISTEN_ADDRESS = "127.0.0.1";
	private const uint16 DEFAULT_LISTEN_PORT = 27042;
	private static bool output_version = false;
	private static string? listen_address = null;
#if !WINDOWS
	private static bool daemonize = false;
#endif

	private delegate void ReadyHandler (bool success);

	const OptionEntry[] options = {
		{ "version", 0, 0, OptionArg.NONE, ref output_version, "Output version information and exit", null },
		{ "listen", 'l', 0, OptionArg.STRING, ref listen_address, "Listen on ADDRESS", "ADDRESS" },
#if !WINDOWS
		{ "daemonize", 'D', 0, OptionArg.NONE, ref daemonize, "Detach and become a daemon", null },
#endif
		{ null }
	};

	private static int main (string[] args) {
		try {
			var ctx = new OptionContext ();
			ctx.set_help_enabled (true);
			ctx.add_main_entries (options, null);
			ctx.parse (ref args);
		} catch (OptionError e) {
			printerr ("%s\n", e.message);
			printerr ("Run '%s --help' to see a full list of available command line options.\n", args[0]);
			return 1;
		}

		if (output_version) {
			stdout.printf ("%s\n", version_string ());
			return 0;
		}

		SocketConnectable connectable;
		string raw_address = (listen_address != null) ? listen_address : DEFAULT_LISTEN_ADDRESS;
#if !WINDOWS
		if (raw_address.has_prefix ("unix:")) {
			string path = raw_address.substring (5);

			UnixSocketAddressType type = UnixSocketAddress.abstract_names_supported ()
				? UnixSocketAddressType.ABSTRACT
				: UnixSocketAddressType.PATH;

			connectable = new UnixSocketAddress.with_type (path, -1, type);
		} else {
#else
		{
#endif
			try {
				connectable = NetworkAddress.parse (raw_address, DEFAULT_LISTEN_PORT);
			} catch (GLib.Error e) {
				printerr ("%s\n", e.message);
				return 1;
			}
		}

		ReadyHandler? on_ready = null;
#if !WINDOWS
		if (daemonize) {
			var sync_fds = new int[2];

			try {
				Unix.open_pipe (sync_fds, 0);
				Unix.set_fd_nonblocking (sync_fds[0], true);
				Unix.set_fd_nonblocking (sync_fds[1], true);
			} catch (GLib.Error e) {
				assert_not_reached ();
			}

			var sync_in = new UnixInputStream (sync_fds[0], true);
			var sync_out = new UnixOutputStream (sync_fds[1], true);

			var pid = Posix.fork ();
			if (pid != 0) {
				try {
					var status = new uint8[1];
					sync_in.read (status);
					return status[0];
				} catch (GLib.Error e) {
					return 2;
				}
			}

			sync_in = null;
			on_ready = (success) => {
				if (success) {
					Posix.setsid ();

					var null_in = Posix.open ("/dev/null", Posix.O_RDONLY);
					var null_out = Posix.open ("/dev/null", Posix.O_WRONLY);
					Posix.dup2 (null_in, Posix.STDIN_FILENO);
					Posix.dup2 (null_out, Posix.STDOUT_FILENO);
					Posix.dup2 (null_out, Posix.STDERR_FILENO);
					Posix.close (null_in);
					Posix.close (null_out);
				}

				var status = new uint8[1];
				status[0] = success ? 0 : 1;
				try {
					sync_out.write (status);
				} catch (GLib.Error e) {
				}
				sync_out = null;
			};
		}
#endif

		return run_application (connectable, on_ready);
	}

	private static int run_application (SocketConnectable connectable, ReadyHandler on_ready) {
		application = new Application ();

		Posix.signal (Posix.Signal.INT, (sig) => {
			application.stop ();
		});
		Posix.signal (Posix.Signal.TERM, (sig) => {
			application.stop ();
		});

		if (on_ready != null) {
			application.ready.connect (() => {
				on_ready (true);
				on_ready = null;
			});
		}

		return application.run (connectable);
	}

	namespace Tcp {
		public extern void enable_nodelay (Socket socket);
	}

	public class Application : Object, HostSession {
		public signal void ready ();

		private Gee.HashMap<AgentSessionId?, AgentSession> agent_sessions =
			new Gee.HashMap<AgentSessionId?, AgentSession> (AgentSessionId.hash, AgentSessionId.equal);

		private SocketService server = new SocketService ();
		private string guid = DBus.generate_guid ();
		private Gee.HashMap<DBusConnection, Client> clients = new Gee.HashMap<DBusConnection, Client> ();

		private Gee.HashMap<uint, Node> node_by_pid = new Gee.HashMap<uint, Node> ();
		private Gee.HashMap<string, Node> node_by_identifier = new Gee.HashMap<string, Node> ();

		private bool spawn_gating_enabled = false;
		private uint next_agent_session_id = 1;

		private Cancellable io_cancellable = new Cancellable ();

		private int exit_code;
		private MainLoop loop;
		private bool stopping;

		construct {
			server.incoming.connect (on_server_connection);
		}

		public int run (SocketConnectable connectable) {
			Idle.add (() => {
				start.begin (connectable);
				return false;
			});

			exit_code = 0;

			loop = new MainLoop ();
			loop.run ();

			return exit_code;
		}

		private async void start (SocketConnectable connectable) {
			var enumerator = connectable.enumerate ();
			SocketAddress? address;
			try {
				while ((address = yield enumerator.next_async (io_cancellable)) != null) {
					SocketAddress effective_address;
					server.add_address (address, SocketType.STREAM, SocketProtocol.DEFAULT, null,
						out effective_address);
				}
			} catch (GLib.Error e) {
				printerr ("Unable to start: %s\n", e.message);
				exit_code = 3;
				stop ();
				return;
			}

			server.start ();

			Idle.add (() => {
				ready ();
				return false;
			});
		}

		public void stop () {
			Idle.add (() => {
				perform_stop.begin ();
				return false;
			});
		}

		public async void perform_stop () {
			if (stopping)
				return;
			stopping = true;

			server.stop ();

			while (clients.size != 0) {
				foreach (var entry in clients.entries) {
					var connection = entry.key;
					var client = entry.value;
					clients.unset (connection);
					try {
						yield connection.flush ();
					} catch (GLib.Error e) {
					}
					client.close ();
					try {
						yield connection.close ();
					} catch (GLib.Error e) {
					}
					break;
				}
			}

			while (agent_sessions.size != 0) {
				foreach (var entry in agent_sessions.entries) {
					var id = entry.key;
					var session = entry.value;
					agent_sessions.unset (id);
					try {
						yield session.close (null);
					} catch (GLib.Error e) {
					}
					break;
				}
			}

			agent_sessions.clear ();

			io_cancellable.cancel ();

			Idle.add (() => {
				loop.quit ();
				return false;
			});
		}

		public async HostApplicationInfo get_frontmost_application (Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Not supported");
		}

		public async HostApplicationInfo[] enumerate_applications (Cancellable? cancellable) throws Error, IOError {
			var result = new HostApplicationInfo[0];
			foreach (var node in node_by_identifier.values)
				result += HostApplicationInfo (node.identifier, node.name, node.pid, node.small_icon, node.large_icon);
			return result;
		}

		public async HostProcessInfo[] enumerate_processes (Cancellable? cancellable) throws Error, IOError {
			var result = new HostProcessInfo[0];
			foreach (var node in node_by_identifier.values)
				result += HostProcessInfo (node.pid, node.name, node.small_icon, node.large_icon);
			return result;
		}

		public async void enable_spawn_gating (Cancellable? cancellable) throws Error, IOError {
			spawn_gating_enabled = true;
		}

		public async void disable_spawn_gating (Cancellable? cancellable) throws Error, IOError {
			spawn_gating_enabled = false;
		}

		public async HostSpawnInfo[] enumerate_pending_spawn (Cancellable? cancellable) throws Error, IOError {
			// TODO: actually implement this
			return {};
		}

		public async HostChildInfo[] enumerate_pending_children (Cancellable? cancellable) throws Error, IOError {
			return {};
		}

		public async uint spawn (string program, HostSpawnOptions options, Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Not supported");
		}

		public async void input (uint pid, uint8[] data, Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Not supported");
		}

		public async void resume (uint pid, Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Not supported");
		}

		public async void kill (uint pid, Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Not supported");
		}

		public async AgentSessionId attach_to (uint pid, Cancellable? cancellable) throws Error, IOError {
			try {
				return yield attach_in_realm (pid, NATIVE, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async AgentSessionId attach_in_realm (uint pid, Realm realm, Cancellable? cancellable) throws Error, IOError {
			Node node = node_by_pid[pid];
			if (node == null)
				throw new Error.PROCESS_NOT_FOUND ("Unable to find process with pid %u", pid);

			var id = AgentSessionId (next_agent_session_id++);
			AgentSession session;

			try {
				yield node.provider.open (id, realm, cancellable);

				session = yield node.connection.get_proxy (null, ObjectPath.from_agent_session_id (id), DBusProxyFlags.NONE,
					cancellable);
			} catch (GLib.Error e) {
				throw new Error.PROTOCOL ("%s", e.message);
			}

			on_agent_session_opened (id, session);

			return id;
		}

		public async InjectorPayloadId inject_library_file (uint pid, string path, string entrypoint, string data,
				Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Not supported");
		}

		public async InjectorPayloadId inject_library_blob (uint pid, uint8[] blob, string entrypoint, string data,
				Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Not supported");
		}

		private bool on_server_connection (SocketConnection connection, Object? source_object) {
			handle_server_connection.begin (connection);
			return true;
		}

		private async void handle_server_connection (SocketConnection socket_connection) throws GLib.Error {
			var socket = socket_connection.socket;
			if (socket.get_family () != UNIX)
				Tcp.enable_nodelay (socket);

			var connection = yield new DBusConnection (socket_connection, guid,
				AUTHENTICATION_SERVER | AUTHENTICATION_ALLOW_ANONYMOUS | DELAY_MESSAGE_PROCESSING,
				null, io_cancellable);
			connection.on_closed.connect (on_connection_closed);

			var client = new Client (connection);
			client.joined.connect (on_client_joined);
			client.register_host_session (this);
			foreach (var entry in agent_sessions.entries)
				client.register_agent_session (entry.key, entry.value);
			clients.set (connection, client);

			connection.start_message_processing ();
		}

		private void on_connection_closed (DBusConnection connection, bool remote_peer_vanished, GLib.Error? error) {
			bool closed_by_us = (!remote_peer_vanished && error == null);
			if (closed_by_us)
				return;

			Client client;
			clients.unset (connection, out client);

			Node? node = client.node;
			if (node != null) {
				node_by_pid.unset (node.pid);
				node_by_identifier.unset (node.identifier);
			}

			client.close ();

			if (client.is_spawn_gating)
				disable_spawn_gating.begin (io_cancellable);

			foreach (var pid in client.orphans)
				kill.begin (pid, io_cancellable);

			foreach (var session_id in client.sessions)
				close_session.begin (session_id);
		}

		private async void close_session (AgentSessionId id) {
			var session = agent_sessions[id];
			if (session == null)
				return;

			try {
				yield session.close (io_cancellable);
			} catch (GLib.Error e) {
			}
		}

		private async void on_client_joined (Client client, HostApplicationInfo info) {
			AgentSessionProvider provider;
			try {
				provider = yield client.connection.get_proxy (null, ObjectPath.AGENT_SESSION_PROVIDER, DBusProxyFlags.NONE,
					io_cancellable);
			} catch (IOError e) {
				return;
			}
			provider.closed.connect (on_agent_session_provider_closed);

			uint pid = info.pid;
			while (node_by_pid.has_key (pid))
				pid++;

			string real_identifier = info.identifier;
			string candidate = real_identifier;
			uint serial = 2;
			while (node_by_identifier.has_key (candidate))
				candidate = "%s%u".printf (real_identifier, serial++);
			string identifier = candidate;

			var node = new Node (pid, identifier, info.name, info.small_icon, info.large_icon, client.connection, provider);
			node_by_pid[pid] = node;
			node_by_identifier[identifier] = node;

			client.node = node;
		}

		private void on_agent_session_provider_closed (AgentSessionId id) {
			AgentSession session;
			var closed_after_opening = agent_sessions.unset (id, out session);
			if (!closed_after_opening)
				return;
			var reason = SessionDetachReason.APPLICATION_REQUESTED;
			on_agent_session_closed (id, session);
			agent_session_destroyed (id, reason);
		}

		private void on_agent_session_opened (AgentSessionId id, AgentSession session) {
			agent_sessions[id] = session;

			DBusConnection connection = ((DBusProxy) session).g_connection;
			foreach (var e in clients.entries) {
				if (e.key != connection)
					e.value.register_agent_session (id, session);
			}
		}

		private void on_agent_session_closed (AgentSessionId id, AgentSession session) {
			DBusConnection connection = ((DBusProxy) session).g_connection;
			foreach (var e in clients.entries) {
				if (e.key != connection)
					e.value.unregister_agent_session (id, session);
			}

			agent_sessions.unset (id);
		}

		private class Client : Object, SaucerSession {
			public signal void joined (HostApplicationInfo info);

			public DBusConnection connection {
				get;
				construct;
			}

			public bool is_spawn_gating {
				get;
				private set;
			}

			public Gee.HashSet<uint> orphans {
				get;
				default = new Gee.HashSet<uint> ();
			}

			public Gee.HashSet<AgentSessionId?> sessions {
				get;
				default = new Gee.HashSet<AgentSessionId?> (AgentSessionId.hash, AgentSessionId.equal);
			}

			public Node? node {
				get;
				set;
			}

			private uint filter_id;
			private Gee.HashSet<uint> registrations = new Gee.HashSet<uint> ();
			private Gee.HashMap<AgentSessionId?, uint> agent_registrations =
				new Gee.HashMap<AgentSessionId?, uint> (AgentSessionId.hash, AgentSessionId.equal);
			private Gee.HashMap<uint32, DBusMessage> method_calls = new Gee.HashMap<uint32, DBusMessage> ();

			public Client (DBusConnection connection) {
				Object (connection: connection);
			}

			construct {
				filter_id = connection.add_filter (on_connection_message);

				try {
					SaucerSession session = this;
					registrations.add (connection.register_object (ObjectPath.SAUCER_SESSION, session));
				} catch (IOError e) {
					assert_not_reached ();
				}
			}

			public void close () {
				agent_registrations.clear ();

				foreach (var registration_id in registrations)
					connection.unregister_object (registration_id);
				registrations.clear ();

				connection.remove_filter (filter_id);
			}

			public void register_host_session (HostSession session) {
				try {
					registrations.add (connection.register_object (ObjectPath.HOST_SESSION, session));
				} catch (IOError e) {
					assert_not_reached ();
				}
			}

			public void register_agent_session (AgentSessionId id, AgentSession session) {
				var proxy = (DBusProxy) session;
				if (proxy.g_connection == connection)
					return;

				try {
					var registration_id = connection.register_object (ObjectPath.from_agent_session_id (id), session);
					registrations.add (registration_id);
					agent_registrations.set (id, registration_id);
				} catch (IOError e) {
					assert_not_reached ();
				}
			}

			public void unregister_agent_session (AgentSessionId id, AgentSession session) {
				var proxy = (DBusProxy) session;
				if (proxy.g_connection == connection)
					return;

				uint registration_id;
				agent_registrations.unset (id, out registration_id);
				registrations.remove (registration_id);
				connection.unregister_object (registration_id);
			}

			public async void join (HostApplicationInfo info, Cancellable? cancellable,
					out SpawnStartState start_state) throws Error {
				start_state = RUNNING;
				joined (info);
			}

			private void schedule_idle (owned ScheduledFunc func) {
				var client = this;
				Idle.add (() => {
					func ();
					client = null;
					return false;
				});
			}

			private delegate void ScheduledFunc ();

			private GLib.DBusMessage on_connection_message (DBusConnection connection, owned DBusMessage message,
					bool incoming) {
				DBusMessage result = message;

				var type = message.get_message_type ();
				DBusMessage call = null;
				switch (type) {
					case DBusMessageType.METHOD_CALL:
						method_calls[message.get_serial ()] = message;
						break;
					case DBusMessageType.METHOD_RETURN:
						method_calls.unset (message.get_reply_serial (), out call);
						break;
					case DBusMessageType.ERROR:
						method_calls.unset (message.get_reply_serial (), out call);
						break;
					case DBusMessageType.SIGNAL:
						break;
					default:
						assert_not_reached ();
				}

				if (type == DBusMessageType.SIGNAL || type == DBusMessageType.ERROR)
					return result;

				string path, iface, member;
				if (call == null) {
					path = message.get_path ();
					iface = message.get_interface ();
					member = message.get_member ();
				} else {
					path = call.get_path ();
					iface = call.get_interface ();
					member = call.get_member ();
				}
				if (iface == "re.frida.HostSession14") {
					if (member == "EnableSpawnGating" && type == DBusMessageType.METHOD_RETURN) {
						schedule_idle (() => {
							is_spawn_gating = true;
						});
					} else if (member == "DisableSpawnGating" && type == DBusMessageType.METHOD_RETURN) {
						schedule_idle (() => {
							is_spawn_gating = false;
						});
					} else if (member == "Spawn" && type == DBusMessageType.METHOD_RETURN) {
						uint32 pid;
						message.get_body ().get ("(u)", out pid);
						schedule_idle (() => {
							orphans.add (pid);
						});
					} else if ((member == "Resume" || member == "Kill") && type == DBusMessageType.METHOD_RETURN) {
						uint32 pid;
						call.get_body ().get ("(u)", out pid);
						schedule_idle (() => {
							orphans.remove (pid);
						});
					} else if (member == "AttachTo" && type == DBusMessageType.METHOD_RETURN) {
						uint32 raw_id;
						message.get_body ().get ("((u))", out raw_id);
						schedule_idle (() => {
							sessions.add (AgentSessionId (raw_id));
						});
					}
				} else if (iface == "re.frida.AgentSession14") {
					uint raw_id;
					path.scanf ("/re/frida/AgentSession/%u", out raw_id);
					if (member == "Close") {
						if (type != DBusMessageType.METHOD_CALL) {
							schedule_idle (() => {
								sessions.remove (AgentSessionId (raw_id));
							});
						}
					}
				}

				return result;
			}
		}

		private class Node : Object {
			public uint pid {
				get;
				construct;
			}

			public string identifier {
				get;
				construct;
			}

			public string name {
				get;
				construct;
			}

			public ImageData small_icon {
				get;
				construct;
			}

			public ImageData large_icon {
				get;
				construct;
			}

			public DBusConnection connection {
				get;
				construct;
			}

			public AgentSessionProvider provider {
				get;
				construct;
			}

			public Node (uint pid, string identifier, string name, ImageData small_icon, ImageData large_icon,
					DBusConnection connection, AgentSessionProvider provider) {
				Object (
					pid: pid,
					identifier: identifier,
					name: name,
					small_icon: small_icon,
					large_icon: large_icon,
					connection: connection,
					provider: provider
				);
			}
		}
	}
}
