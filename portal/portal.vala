namespace Frida.Portal {
	private static Application application;

	private const string DEFAULT_CONTROL_ADDRESS = "127.0.0.1";
	private const uint16 DEFAULT_CONTROL_PORT = 27042;
	private const string DEFAULT_CLUSTER_ADDRESS = "127.0.0.1";
	private const uint16 DEFAULT_CLUSTER_PORT = 27043;
	private static bool output_version = false;
	private static string? control_address = null;
	private static string? control_certpath = null;
	private static string? control_token = null;
	private static string? cluster_address = null;
	private static string? cluster_certpath = null;
	private static string? cluster_token = null;
#if !WINDOWS
	private static bool daemonize = false;
#endif

	private delegate void ReadyHandler (bool success);

	const OptionEntry[] options = {
		{ "version", 0, 0, OptionArg.NONE, ref output_version, "Output version information and exit", null },
		{ "control-endpoint", 0, 0, OptionArg.STRING, ref control_address, "Expose control endpoint on ADDRESS", "ADDRESS" },
		{ "control-certificate", 0, 0, OptionArg.FILENAME, ref control_certpath, "Enable TLS on control endpoint using CERTIFICATE",
			"CERTIFICATE" },
		{ "control-token", 0, 0, OptionArg.STRING, ref control_token, "Enable authentication on control endpoint using TOKEN",
			"TOKEN" },
		{ "cluster-endpoint", 0, 0, OptionArg.STRING, ref cluster_address, "Expose cluster endpoint on ADDRESS", "ADDRESS" },
		{ "cluster-certificate", 0, 0, OptionArg.FILENAME, ref cluster_certpath, "Enable TLS on cluster endpoint using CERTIFICATE",
			"CERTIFICATE" },
		{ "cluster-token", 0, 0, OptionArg.STRING, ref cluster_token, "Enable authentication on cluster endpoint using TOKEN",
			"TOKEN" },
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

		EndpointParameters control_params, cluster_params;
		try {
			control_params = EndpointParameters.parse (CONTROL, control_address, DEFAULT_CONTROL_ADDRESS, DEFAULT_CONTROL_PORT,
				control_certpath, control_token);
			cluster_params = EndpointParameters.parse (CLUSTER, cluster_address, DEFAULT_CLUSTER_ADDRESS, DEFAULT_CLUSTER_PORT,
				cluster_certpath, cluster_token);
		} catch (GLib.Error e) {
			printerr ("%s\n", e.message);
			return 2;
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
					return 3;
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

		application = new Application (control_params, cluster_params);

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

		return application.run ();
	}

	namespace Tcp {
		public extern void enable_nodelay (Socket socket);
	}

	private class Application : Object {
		public signal void ready ();

		public EndpointParameters control_parameters {
			get;
			construct;
		}

		public EndpointParameters cluster_parameters {
			get;
			construct;
		}

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

		public Application (EndpointParameters control_parameters, EndpointParameters cluster_parameters) {
			Object (control_parameters: control_parameters, cluster_parameters: cluster_parameters);
		}

		construct {
			server.incoming.connect (on_incoming_connection);
		}

		public int run () {
			Idle.add (() => {
				start.begin ();
				return false;
			});

			exit_code = 0;

			loop = new MainLoop ();
			loop.run ();

			return exit_code;
		}

		private async void start () {
			try {
				yield add_endpoint (control_parameters);
				yield add_endpoint (cluster_parameters);
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

		private async void add_endpoint (EndpointParameters parameters) throws GLib.Error {
			var enumerator = parameters.connectable.enumerate ();
			SocketAddress? address;
			while ((address = yield enumerator.next_async (io_cancellable)) != null) {
				SocketAddress effective_address;
				server.add_address (address, SocketType.STREAM, SocketProtocol.DEFAULT, parameters, out effective_address);
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
			var parameters = (EndpointParameters) source_object;
			on_connection_opened.begin (connection, parameters);
			return true;
		}

		private async void on_connection_opened (SocketConnection socket_connection,
				EndpointParameters parameters) throws GLib.Error {
			var socket = socket_connection.socket;
			if (socket.get_family () != UNIX)
				Tcp.enable_nodelay (socket);

			IOStream stream = socket_connection;

			TlsCertificate? certificate = parameters.certificate;
			if (certificate != null) {
				var tls_conn = TlsServerConnection.new (stream, certificate);
				yield tls_conn.handshake_async (Priority.DEFAULT, io_cancellable);
				stream = tls_conn;
			}

			var connection = yield new DBusConnection (stream, guid,
				AUTHENTICATION_SERVER | AUTHENTICATION_ALLOW_ANONYMOUS | DELAY_MESSAGE_PROCESSING, null, io_cancellable);
			connection.on_closed.connect (on_connection_closed);

			Peer peer;
			if (parameters.token_hash != null)
				peer = setup_unauthorized_peer (connection, parameters);
			else
				peer = yield setup_authorized_peer (connection, parameters);
			peers[connection] = peer;
		}

		private void on_connection_closed (DBusConnection connection, bool remote_peer_vanished, GLib.Error? error) {
			Peer peer;
			peers.unset (connection, out peer);
			peer.close ();
		}

		private Peer setup_unauthorized_peer (DBusConnection connection, EndpointParameters parameters) {
			var channel = new AuthenticationChannel (this, connection, parameters);

			try {
				if (parameters.protocol == CONTROL) {
					HostSession host_session = new UnauthorizedHostSession ();
					channel.take_registration (connection.register_object (ObjectPath.HOST_SESSION, host_session));
				} else {
					PortalSession portal_session = new UnauthorizedPortalSession ();
					channel.take_registration (connection.register_object (ObjectPath.PORTAL_SESSION, portal_session));
				}
			} catch (GLib.Error e) {
				assert_not_reached ();
			}

			connection.start_message_processing ();

			return channel;
		}

		private async void promote_authentication_channel (AuthenticationChannel channel) throws GLib.Error {
			DBusConnection connection = channel.connection;

			peers.unset (connection);
			channel.close ();

			peers[connection] = yield setup_authorized_peer (connection, channel.parameters);
		}

		private void kick_authentication_channel (AuthenticationChannel channel) {
			Idle.add (() => {
				channel.connection.close.begin (io_cancellable);
				return false;
			});
		}

		private async Peer setup_authorized_peer (DBusConnection connection, EndpointParameters parameters) throws GLib.Error {
			if (parameters.protocol == CONTROL)
				return setup_control_channel (connection);
			else
				return yield setup_cluster_node (connection);
		}

		private ControlChannel setup_control_channel (DBusConnection connection) {
			var channel = new ControlChannel (this, connection);

			connection.start_message_processing ();

			return channel;
		}

		private void teardown_control_channel (ControlChannel channel) {
			foreach (var session in channel.sessions.values)
				session.close.begin (io_cancellable);

			disable_spawn_gating (channel);
		}

		private async ClusterNode setup_cluster_node (DBusConnection connection) throws GLib.Error {
			var node = new ClusterNode (this, connection);
			node.session_closed.connect (on_agent_session_closed);

			connection.start_message_processing ();

			node.session_provider = yield connection.get_proxy (null, ObjectPath.AGENT_SESSION_PROVIDER,
				DBusProxyFlags.NONE, io_cancellable);

			return node;
		}

		private void teardown_cluster_node (ClusterNode node) {
			foreach (var id in node.sessions) {
				ControlChannel c;
				if (sessions.unset (id, out c)) {
					c.unregister_agent_session (id);
					c.agent_session_destroyed (id, SessionDetachReason.PROCESS_TERMINATED);
				}
			}

			ClusterMembership? membership = node.membership;
			if (membership != null) {
				node_by_pid.unset (membership.pid);
				node_by_identifier.unset (membership.identifier);

				PendingSpawn spawn;
				if (pending_spawn.unset (membership.pid, out spawn))
					notify_spawn_removed (spawn.info);
			}
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
				throw new Error.PROTOCOL ("Already joined");
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

		private interface Peer : Object {
			public abstract void close ();
		}

		private class AuthenticationChannel : Object, Peer, AuthenticationService {
			public weak Application parent {
				get;
				construct;
			}

			public DBusConnection connection {
				get;
				construct;
			}

			public EndpointParameters parameters {
				get;
				construct;
			}

			private Gee.Collection<uint> registrations = new Gee.ArrayList<uint> ();

			public AuthenticationChannel (Application parent, DBusConnection connection, EndpointParameters parameters) {
				Object (
					parent: parent,
					connection: connection,
					parameters: parameters
				);
			}

			public void close () {
				foreach (var id in registrations)
					connection.unregister_object (id);
				registrations.clear ();
			}

			public void take_registration (uint id) {
				registrations.add (id);
			}

			public async void authenticate (string token, Cancellable? cancellable) throws GLib.Error {
				string actual_hash = Checksum.compute_for_string (SHA256, token);
				string expected_hash = parameters.token_hash;

				uint accumulator = 0;
				for (uint i = 0; i != actual_hash.length; i++) {
					accumulator |= actual_hash[i] ^ expected_hash[i];
				}

				if (accumulator == 0) {
					yield parent.promote_authentication_channel (this);
				} else {
					parent.kick_authentication_channel (this);
					throw new Error.INVALID_ARGUMENT ("Incorrect token");
				}
			}
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
				parent.teardown_control_channel (this);

				agent_registrations.clear ();

				foreach (var id in registrations)
					connection.unregister_object (id);
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
				parent.teardown_cluster_node (this);

				foreach (var id in registrations)
					connection.unregister_object (id);
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

	private enum EndpointProtocol {
		CONTROL,
		CLUSTER
	}

	private class EndpointParameters : Object {
		public EndpointProtocol protocol {
			get;
			construct;
		}

		public SocketConnectable connectable {
			get;
			construct;
		}

		public TlsCertificate? certificate {
			get;
			construct;
		}

		public string? token_hash {
			get;
			construct;
		}

		public EndpointParameters (EndpointProtocol protocol, SocketConnectable connectable, TlsCertificate? certificate,
				string? token) {
			Object (
				protocol: protocol,
				connectable: connectable,
				certificate: certificate,
				token_hash: (token != null) ? Checksum.compute_for_string (SHA256, token) : null
			);
		}

		public static EndpointParameters parse (EndpointProtocol protocol, string? configured_address, string default_address,
				uint16 default_port, string? certificate_path, string? token) throws GLib.Error {
			SocketConnectable connectable = parse_socket_address (configured_address, default_address, default_port);

			TlsCertificate? certificate = (certificate_path != null)
				? new TlsCertificate.from_file (certificate_path)
				: null;

			return new EndpointParameters (protocol, connectable, certificate, token);
		}
	}

	private class UnauthorizedHostSession : Object, HostSession {
		public async HostApplicationInfo get_frontmost_application (Cancellable? cancellable) throws Error, IOError {
			throw_not_authorized ();
		}

		public async HostApplicationInfo[] enumerate_applications (Cancellable? cancellable) throws Error, IOError {
			throw_not_authorized ();
		}

		public async HostProcessInfo[] enumerate_processes (Cancellable? cancellable) throws Error, IOError {
			throw_not_authorized ();
		}

		public async void enable_spawn_gating (Cancellable? cancellable) throws Error, IOError {
			throw_not_authorized ();
		}

		public async void disable_spawn_gating (Cancellable? cancellable) throws Error, IOError {
			throw_not_authorized ();
		}

		public async HostSpawnInfo[] enumerate_pending_spawn (Cancellable? cancellable) throws Error, IOError {
			throw_not_authorized ();
		}

		public async HostChildInfo[] enumerate_pending_children (Cancellable? cancellable) throws Error, IOError {
			throw_not_authorized ();
		}

		public async uint spawn (string program, HostSpawnOptions options, Cancellable? cancellable) throws Error, IOError {
			throw_not_authorized ();
		}

		public async void input (uint pid, uint8[] data, Cancellable? cancellable) throws Error, IOError {
			throw_not_authorized ();
		}

		public async void resume (uint pid, Cancellable? cancellable) throws Error, IOError {
			throw_not_authorized ();
		}

		public async void kill (uint pid, Cancellable? cancellable) throws Error, IOError {
			throw_not_authorized ();
		}

		public async AgentSessionId attach_to (uint pid, Cancellable? cancellable) throws Error, IOError {
			throw_not_authorized ();
		}

		public async AgentSessionId attach_in_realm (uint pid, Realm realm, Cancellable? cancellable) throws Error, IOError {
			throw_not_authorized ();
		}

		public async InjectorPayloadId inject_library_file (uint pid, string path, string entrypoint, string data,
				Cancellable? cancellable) throws Error, IOError {
			throw_not_authorized ();
		}

		public async InjectorPayloadId inject_library_blob (uint pid, uint8[] blob, string entrypoint, string data,
				Cancellable? cancellable) throws Error, IOError {
			throw_not_authorized ();
		}
	}

	private class UnauthorizedPortalSession : Object, PortalSession {
		public async void join (HostApplicationInfo app, Cancellable? cancellable, out SpawnStartState start_state) throws Error {
			throw_not_authorized ();
		}
	}

	[NoReturn]
	private void throw_not_authorized () throws Error {
		throw new Error.PERMISSION_DENIED ("Not authorized, authentication required");
	}

	private SocketConnectable parse_socket_address (string? configured_address, string default_address,
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
