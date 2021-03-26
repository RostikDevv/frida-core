namespace Frida {
	public abstract class BaseAgentSession : Object, AgentSession {
		public signal void closed ();
		public signal void script_eternalized (Gum.Script script);

		public weak ProcessInvader invader {
			get;
			construct;
		}

		private Promise<bool> close_request;
		private Promise<bool> flush_complete = new Promise<bool> ();

		private bool child_gating_enabled = false;
		private ScriptEngine script_engine;

		construct {
			script_engine = new ScriptEngine (invader);
			script_engine.message_from_script.connect (on_message_from_script);
			script_engine.message_from_debugger.connect (on_message_from_debugger);
		}

		public async void close (Cancellable? cancellable) throws Error, IOError {
			while (close_request != null) {
				try {
					yield close_request.future.wait_async (cancellable);
					return;
				} catch (GLib.Error e) {
					assert (e is IOError.CANCELLED);
					cancellable.set_error_if_cancelled ();
				}
			}
			close_request = new Promise<bool> ();

			try {
				yield disable_child_gating (cancellable);
			} catch (GLib.Error e) {
				assert_not_reached ();
			}

			yield script_engine.flush ();
			flush_complete.resolve (true);

			yield script_engine.close ();
			script_engine.message_from_script.disconnect (on_message_from_script);
			script_engine.message_from_debugger.disconnect (on_message_from_debugger);

			closed ();

			close_request.resolve (true);
		}

		public async void flush () {
			if (close_request == null)
				close.begin (null);

			try {
				yield flush_complete.future.wait_async (null);
			} catch (GLib.Error e) {
				assert_not_reached ();
			}
		}

		public async void prepare_for_termination (TerminationReason reason) {
			yield script_engine.prepare_for_termination (reason);
		}

		public void unprepare_for_termination () {
			script_engine.unprepare_for_termination ();
		}

		public async void enable_child_gating (Cancellable? cancellable) throws Error, IOError {
			check_open ();

			if (child_gating_enabled)
				return;

			invader.acquire_child_gating ();

			child_gating_enabled = true;
		}

		public async void disable_child_gating (Cancellable? cancellable) throws Error, IOError {
			if (!child_gating_enabled)
				return;

			invader.release_child_gating ();

			child_gating_enabled = false;
		}

		public async AgentScriptId create_script (string name, string source, Cancellable? cancellable) throws Error, IOError {
			check_open ();

			var options = new ScriptOptions ();
			if (name != "")
				options.name = name;

			var instance = yield script_engine.create_script (source, null, options);
			return instance.script_id;
		}

		public async AgentScriptId create_script_with_options (string source, AgentScriptOptions options,
				Cancellable? cancellable) throws Error, IOError {
			check_open ();

			var instance = yield script_engine.create_script (source, null, ScriptOptions._deserialize (options.data));
			return instance.script_id;
		}

		public async AgentScriptId create_script_from_bytes (uint8[] bytes, Cancellable? cancellable) throws Error, IOError {
			check_open ();

			var instance = yield script_engine.create_script (null, new Bytes (bytes), new ScriptOptions ());
			return instance.script_id;
		}

		public async AgentScriptId create_script_from_bytes_with_options (uint8[] bytes, AgentScriptOptions options,
				Cancellable? cancellable) throws Error, IOError {
			check_open ();

			var instance = yield script_engine.create_script (null, new Bytes (bytes),
				ScriptOptions._deserialize (options.data));
			return instance.script_id;
		}

		public async uint8[] compile_script (string name, string source, Cancellable? cancellable) throws Error, IOError {
			check_open ();

			var options = new ScriptOptions ();
			if (name != "")
				options.name = name;

			var bytes = yield script_engine.compile_script (source, options);
			return bytes.get_data ();
		}

		public async uint8[] compile_script_with_options (string source, AgentScriptOptions options,
				Cancellable? cancellable) throws Error, IOError {
			check_open ();

			var bytes = yield script_engine.compile_script (source, ScriptOptions._deserialize (options.data));
			return bytes.get_data ();
		}

		public async void destroy_script (AgentScriptId script_id, Cancellable? cancellable) throws Error, IOError {
			check_open ();

			yield script_engine.destroy_script (script_id);
		}

		public async void load_script (AgentScriptId script_id, Cancellable? cancellable) throws Error, IOError {
			check_open ();

			yield script_engine.load_script (script_id);
		}

		public async void eternalize_script (AgentScriptId script_id, Cancellable? cancellable) throws Error, IOError {
			check_open ();

			var script = script_engine.eternalize_script (script_id);
			script_eternalized (script);
		}

		public async void post_to_script (AgentScriptId script_id, string message, bool has_data, uint8[] data,
				Cancellable? cancellable) throws Error, IOError {
			check_open ();

			script_engine.post_to_script (script_id, message, has_data ? new Bytes (data) : null);
		}

		public async void enable_debugger (Cancellable? cancellable) throws Error, IOError {
			check_open ();

			script_engine.enable_debugger ();
		}

		public async void disable_debugger (Cancellable? cancellable) throws Error, IOError {
			check_open ();

			script_engine.disable_debugger ();
		}

		public async void post_message_to_debugger (string message, Cancellable? cancellable) throws Error, IOError {
			check_open ();

			script_engine.post_message_to_debugger (message);
		}

		public async void enable_jit (Cancellable? cancellable) throws Error, IOError {
			check_open ();

			script_engine.enable_jit ();
		}

		private void check_open () throws Error {
			if (close_request != null)
				throw new Error.INVALID_OPERATION ("Session is closing");
		}

		private void on_message_from_script (AgentScriptId script_id, string message, Bytes? data) {
			bool has_data = data != null;
			var data_param = has_data ? data.get_data () : new uint8[0];
			this.message_from_script (script_id, message, has_data, data_param);
		}

		private void on_message_from_debugger (string message) {
			this.message_from_debugger (message);
		}
	}
}
