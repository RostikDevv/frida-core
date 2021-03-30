namespace Frida.Portal {
	private static Application application;

	private const string DEFAULT_CONTROL_ADDRESS = "127.0.0.1";
	private const uint16 DEFAULT_CONTROL_PORT = 27042;
	private const string DEFAULT_CLUSTER_ADDRESS = "127.0.0.1";
	private const uint16 DEFAULT_CLUSTER_PORT = 27043;
	private static bool output_version = false;
	private static string? control_address = null;
	private static string? cluster_address = null;
#if !WINDOWS
	private static bool daemonize = false;
#endif

	private delegate void ReadyHandler (bool success);

	const OptionEntry[] options = {
		{ "version", 0, 0, OptionArg.NONE, ref output_version, "Output version information and exit", null },
		{ "control-endpoint", 0, 0, OptionArg.STRING, ref control_address, "Expose frida-server compatible endpoint on ADDRESS", "ADDRESS" },
		{ "cluster-endpoint", 0, 0, OptionArg.STRING, ref cluster_address, "Expose cluster endpoint on ADDRESS", "ADDRESS" },
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

		SocketConnectable control_connectable, cluster_connectable;
		try {
			control_connectable = parse_socket_address (control_address, DEFAULT_CONTROL_ADDRESS, DEFAULT_CONTROL_PORT);
			cluster_connectable = parse_socket_address (cluster_address, DEFAULT_CLUSTER_ADDRESS, DEFAULT_CLUSTER_PORT);
		} catch (GLib.Error e) {
			printerr ("%s\n", e.message);
			return 1;
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

		return run_application (control_connectable, cluster_connectable, on_ready);
	}

	private static int run_application (SocketConnectable control_connectable, SocketConnectable cluster_connectable,
			ReadyHandler on_ready) {
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

		return application.run (control_connectable, cluster_connectable);
	}

	namespace Tcp {
		public extern void enable_nodelay (Socket socket);
	}

	public class Application : Object {
		public signal void ready ();

		private SocketService server = new SocketService ();
		private string guid = DBus.generate_guid ();
		private Gee.Map<DBusConnection, Peer> peers = new Gee.HashMap<DBusConnection, Peer> ();

		private Gee.Map<uint, ClusterNode> node_by_pid = new Gee.HashMap<uint, ClusterNode> ();
		private Gee.Map<string, ClusterNode> node_by_identifier = new Gee.HashMap<string, ClusterNode> ();

		private Gee.Set<ControlChannel> spawn_gaters = new Gee.HashSet<ControlChannel> ();
		private Gee.Map<uint, PendingSpawn> pending_spawn = new Gee.HashMap<uint, PendingSpawn> ();
		private Gee.Map<AgentSessionId?, ControlChannel> sessions =
			new Gee.HashMap<AgentSessionId?, ControlChannel> (AgentSessionId.hash, AgentSessionId.equal);

		private uint next_agent_session_id = 1;

		private Cancellable io_cancellable = new Cancellable ();

		private int exit_code;
		private MainLoop loop;
		private bool stopping;

		construct {
			server.incoming.connect (on_incoming_connection);
		}

		public int run (SocketConnectable control_connectable, SocketConnectable cluster_connectable) {
			Idle.add (() => {
				start.begin (control_connectable, cluster_connectable);
				return false;
			});

			exit_code = 0;

			loop = new MainLoop ();
			loop.run ();

			return exit_code;
		}

		private async void start (SocketConnectable control_connectable, SocketConnectable cluster_connectable) {
			try {
				yield listen_on (control_connectable, new ControlSourceTag ());
				yield listen_on (cluster_connectable, new ClusterSourceTag ());
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

		private async void listen_on (SocketConnectable connectable, Object source) throws GLib.Error {
			var enumerator = connectable.enumerate ();
			SocketAddress? address;
			while ((address = yield enumerator.next_async (io_cancellable)) != null) {
				SocketAddress effective_address;
				server.add_address (address, SocketType.STREAM, SocketProtocol.DEFAULT, source, out effective_address);
			}
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

			foreach (var peer in peers.values.to_array ())
				peer.close ();
			peers.clear ();

			io_cancellable.cancel ();

			Idle.add (() => {
				loop.quit ();
				return false;
			});
		}

		private bool on_incoming_connection (SocketConnection connection, Object? source_object) {
			on_connection_opened.begin (connection, source_object);
			return true;
		}

		private async void on_connection_opened (SocketConnection socket_connection, Object? source_object) throws GLib.Error {
			var socket = socket_connection.socket;
			if (socket.get_family () != UNIX)
				Tcp.enable_nodelay (socket);

			var connection = yield new DBusConnection (socket_connection, guid,
				AUTHENTICATION_SERVER | AUTHENTICATION_ALLOW_ANONYMOUS | DELAY_MESSAGE_PROCESSING,
				null, io_cancellable);
			connection.on_closed.connect (on_connection_closed);

			Peer peer;
			if (source_object is ControlSourceTag) {
				var channel = new ControlChannel (this, connection);
				peer = channel;

				connection.start_message_processing ();
			} else {
				assert (source_object is ClusterSourceTag);

				var node = new ClusterNode (this, connection);
				node.session_closed.connect (on_agent_session_closed);
				peer = node;

				connection.start_message_processing ();

				node.session_provider = yield connection.get_proxy (null, ObjectPath.AGENT_SESSION_PROVIDER,
					DBusProxyFlags.NONE, io_cancellable);
			}
			peers.set (connection, peer);
		}

		private void on_connection_closed (DBusConnection connection, bool remote_peer_vanished, GLib.Error? error) {
			bool closed_by_us = (!remote_peer_vanished && error == null);
			if (closed_by_us)
				return;

			Peer peer;
			peers.unset (connection, out peer);

			ControlChannel? channel = peer as ControlChannel;
			if (channel != null) {
				foreach (var session in channel.sessions.values)
					session.close.begin (io_cancellable);

				disable_spawn_gating (channel);
			} else {
				assert (peer is ClusterNode);
				ClusterNode node = (ClusterNode) peer;
				ClusterMembership membership = node.membership;

				foreach (var id in node.sessions) {
					ControlChannel c;
					if (sessions.unset (id, out c)) {
						c.unregister_agent_session (id);
						c.agent_session_destroyed (id, SessionDetachReason.PROCESS_TERMINATED);
					}
				}

				node_by_pid.unset (membership.pid);
				node_by_identifier.unset (membership.identifier);

				PendingSpawn spawn;
				if (pending_spawn.unset (membership.pid, out spawn))
					notify_spawn_removed (spawn.info);
			}

			peer.close ();
		}

		private HostApplicationInfo[] enumerate_applications () {
			Gee.Collection<ClusterNode> nodes = node_by_identifier.values;
			var result = new HostApplicationInfo[nodes.size];
			int i = 0;
			foreach (var node in nodes) {
				ClusterMembership m = node.membership;
				result[i++] = HostApplicationInfo (m.identifier, m.name, m.pid, m.small_icon, m.large_icon);
			}
			return result;
		}

		private HostProcessInfo[] enumerate_processes () {
			Gee.Collection<ClusterNode> nodes = node_by_identifier.values;
			var result = new HostProcessInfo[nodes.size];
			int i = 0;
			foreach (var node in nodes) {
				ClusterMembership m = node.membership;
				result[i++] = HostProcessInfo (m.pid, m.name, m.small_icon, m.large_icon);
			}
			return result;
		}

		private void enable_spawn_gating (ControlChannel requester) {
			spawn_gaters.add (requester);
			foreach (var spawn in pending_spawn.values)
				spawn.pending_approvers.add (requester);
		}

		private void disable_spawn_gating (ControlChannel requester) {
			if (spawn_gaters.remove (requester)) {
				foreach (uint pid in pending_spawn.keys.to_array ())
					resume (pid, requester);
			}
		}

		private HostSpawnInfo[] enumerate_pending_spawn () {
			var result = new HostSpawnInfo[pending_spawn.size];
			var i = 0;
			foreach (var spawn in pending_spawn.values)
				result[i++] = spawn.info;
			return result;
		}

		private void resume (uint pid, ControlChannel requester) {
			PendingSpawn spawn = pending_spawn[pid];
			if (spawn == null)
				return;

			var approvers = spawn.pending_approvers;
			approvers.remove (requester);
			if (approvers.is_empty) {
				pending_spawn.unset (pid);

				var node = node_by_pid[pid];
				assert (node != null);
				node.resume ();

				notify_spawn_removed (spawn.info);
			}
		}

		private void kill (uint pid) {
			var node = node_by_pid[pid];
			if (node == null)
				return;

			node.kill ();
		}

		private async AgentSession attach (uint pid, Realm realm, ControlChannel requester, Cancellable? cancellable,
				out AgentSessionId id) throws Error, IOError {
			var node = node_by_pid[pid];
			if (node == null)
				throw new Error.PROCESS_NOT_FOUND ("Unable to find process with pid %u", pid);

			id = AgentSessionId (next_agent_session_id++);

			var session = yield node.open_session (id, realm, cancellable);
			sessions[id] = requester;

			return session;
		}

		private async void handle_join_request (ClusterNode node, HostApplicationInfo app, Cancellable? cancellable,
				out SpawnStartState start_state) throws Error {
			if (node.membership != null)
				throw new Error.PROTOCOL ("Node has already joined");
			if (node.session_provider == null)
				throw new Error.PROTOCOL ("Missing session provider");

			uint pid = app.pid;
			while (node_by_pid.has_key (pid))
				pid++;

			string real_identifier = app.identifier;
			string candidate = real_identifier;
			uint serial = 2;
			while (node_by_identifier.has_key (candidate))
				candidate = "%s[%u]".printf (real_identifier, serial++);
			string identifier = candidate;

			node.membership = new ClusterMembership (pid, identifier, app.name, app.small_icon, app.large_icon);

			node_by_pid[pid] = node;
			node_by_identifier[identifier] = node;

			if (spawn_gaters.is_empty) {
				start_state = RUNNING;
			} else {
				start_state = SUSPENDED;

				var spawn = new PendingSpawn (pid, identifier, spawn_gaters.iterator ());
				pending_spawn[pid] = spawn;
				notify_spawn_added (spawn.info);
			}
		}

		private void notify_spawn_added (HostSpawnInfo info) {
			foreach (ControlChannel channel in spawn_gaters)
				channel.spawn_added (info);
		}

		private void notify_spawn_removed (HostSpawnInfo info) {
			foreach (ControlChannel channel in spawn_gaters)
				channel.spawn_removed (info);
		}

		private void on_agent_session_closed (AgentSessionId id) {
			ControlChannel channel;
			if (sessions.unset (id, out channel)) {
				channel.unregister_agent_session (id);
				channel.agent_session_destroyed (id, SessionDetachReason.APPLICATION_REQUESTED);
			}
		}

		private class ControlSourceTag : Object {
		}

		private class ClusterSourceTag : Object {
		}

		private interface Peer : Object {
			public abstract void close ();
		}

		private class ControlChannel : Object, Peer, HostSession {
			public weak Application parent {
				get;
				construct;
			}

			public DBusConnection connection {
				get;
				construct;
			}

			public Gee.Map<AgentSessionId?, AgentSession> sessions {
				get;
				default = new Gee.HashMap<AgentSessionId?, AgentSession> (AgentSessionId.hash, AgentSessionId.equal);
			}

			private Gee.Set<uint> registrations = new Gee.HashSet<uint> ();
			private Gee.Map<AgentSessionId?, uint> agent_registrations =
				new Gee.HashMap<AgentSessionId?, uint> (AgentSessionId.hash, AgentSessionId.equal);

			public ControlChannel (Application parent, DBusConnection connection) {
				Object (parent: parent, connection: connection);
			}

			construct {
				try {
					HostSession session = this;
					registrations.add (connection.register_object (ObjectPath.HOST_SESSION, session));
				} catch (IOError e) {
					assert_not_reached ();
				}
			}

			public void close () {
				agent_registrations.clear ();

				foreach (var registration_id in registrations)
					connection.unregister_object (registration_id);
				registrations.clear ();
			}

			public async HostApplicationInfo get_frontmost_application (Cancellable? cancellable) throws Error, IOError {
				throw new Error.NOT_SUPPORTED ("Not supported");
			}

			public async HostApplicationInfo[] enumerate_applications (Cancellable? cancellable) throws Error, IOError {
				return parent.enumerate_applications ();
			}

			public async HostProcessInfo[] enumerate_processes (Cancellable? cancellable) throws Error, IOError {
				return parent.enumerate_processes ();
			}

			public async void enable_spawn_gating (Cancellable? cancellable) throws Error, IOError {
				parent.enable_spawn_gating (this);
			}

			public async void disable_spawn_gating (Cancellable? cancellable) throws Error, IOError {
				parent.disable_spawn_gating (this);
			}

			public async HostSpawnInfo[] enumerate_pending_spawn (Cancellable? cancellable) throws Error, IOError {
				return parent.enumerate_pending_spawn ();
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
				parent.resume (pid, this);
			}

			public async void kill (uint pid, Cancellable? cancellable) throws Error, IOError {
				parent.kill (pid);
			}

			public async AgentSessionId attach_to (uint pid, Cancellable? cancellable) throws Error, IOError {
				try {
					return yield attach_in_realm (pid, NATIVE, cancellable);
				} catch (GLib.Error e) {
					throw_dbus_error (e);
				}
			}

			public async AgentSessionId attach_in_realm (uint pid, Realm realm, Cancellable? cancellable) throws Error, IOError {
				AgentSessionId id;
				var session = yield parent.attach (pid, realm, this, cancellable, out id);

				register_agent_session (id, session);

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

			private void register_agent_session (AgentSessionId id, AgentSession session) {
				try {
					sessions[id] = session;

					var registration_id = connection.register_object (ObjectPath.from_agent_session_id (id), session);
					registrations.add (registration_id);

					agent_registrations.set (id, registration_id);
				} catch (IOError e) {
					assert_not_reached ();
				}
			}

			public void unregister_agent_session (AgentSessionId id) {
				uint registration_id;
				agent_registrations.unset (id, out registration_id);

				registrations.remove (registration_id);
				connection.unregister_object (registration_id);

				sessions.unset (id);
			}
		}

		private class ClusterNode : Object, Peer, PortalSession {
			public signal void session_closed (AgentSessionId id);

			public weak Application parent {
				get;
				construct;
			}

			public ClusterMembership? membership {
				get;
				set;
			}

			public DBusConnection connection {
				get;
				construct;
			}

			public AgentSessionProvider? session_provider {
				get {
					return _session_provider;
				}
				set {
					if (_session_provider != null)
						_session_provider.closed.disconnect (on_session_closed);
					_session_provider = value;
					_session_provider.closed.connect (on_session_closed);
				}
			}
			private AgentSessionProvider? _session_provider;

			public Gee.Set<AgentSessionId?> sessions {
				get;
				default = new Gee.HashSet<AgentSessionId?> (AgentSessionId.hash, AgentSessionId.equal);
			}

			private Gee.Set<uint> registrations = new Gee.HashSet<uint> ();

			public ClusterNode (Application parent, DBusConnection connection) {
				Object (parent: parent, connection: connection);
			}

			construct {
				try {
					PortalSession session = this;
					registrations.add (connection.register_object (ObjectPath.PORTAL_SESSION, session));
				} catch (IOError e) {
					assert_not_reached ();
				}
			}

			public void close () {
				foreach (var registration_id in registrations)
					connection.unregister_object (registration_id);
				registrations.clear ();
			}

			public async void join (HostApplicationInfo app, Cancellable? cancellable,
					out SpawnStartState start_state) throws Error {
				yield parent.handle_join_request (this, app, cancellable, out start_state);
			}

			public async AgentSession open_session (AgentSessionId id, Realm realm,
					Cancellable? cancellable) throws Error, IOError {
				AgentSession session;
				try {
					yield session_provider.open (id, realm, cancellable);

					session = yield connection.get_proxy (null, ObjectPath.from_agent_session_id (id),
						DBusProxyFlags.NONE, cancellable);
				} catch (GLib.Error e) {
					throw new Error.PROTOCOL ("%s", e.message);
				}

				sessions.add (id);

				return session;
			}

			private void on_session_closed (AgentSessionId id) {
				if (sessions.remove (id))
					session_closed (id);
			}
		}

		private class ClusterMembership : Object {
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

			public PortalSession portal_session {
				get;
				construct;
			}

			public AgentSessionProvider provider {
				get;
				construct;
			}

			public ClusterMembership (uint pid, string identifier, string name, ImageData small_icon, ImageData large_icon) {
				Object (
					pid: pid,
					identifier: identifier,
					name: name,
					small_icon: small_icon,
					large_icon: large_icon
				);
			}
		}

		private class PendingSpawn {
			public HostSpawnInfo info {
				get;
				private set;
			}

			public Gee.Set<ControlChannel> pending_approvers {
				get;
				default = new Gee.HashSet<ControlChannel> ();
			}

			public PendingSpawn (uint pid, string identifier, Gee.Iterator<ControlChannel> gaters) {
				info = HostSpawnInfo (pid, identifier);
				pending_approvers.add_all_iterator (gaters);
			}
		}
	}

	private static SocketConnectable parse_socket_address (string? configured_address, string default_address,
			uint16 default_port) throws GLib.Error {
		string address = (configured_address != null) ? configured_address : default_address;
#if !WINDOWS
		if (address.has_prefix ("unix:")) {
			string path = address.substring (5);

			UnixSocketAddressType type = UnixSocketAddress.abstract_names_supported ()
				? UnixSocketAddressType.ABSTRACT
				: UnixSocketAddressType.PATH;

			return new UnixSocketAddress.with_type (path, -1, type);
		} else {
#else
		{
#endif
			return NetworkAddress.parse (address, default_port);
		}
	}
}
