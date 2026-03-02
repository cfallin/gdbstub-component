//! Bindings for Wasmtime's debugger API.

use wstd::runtime::AsyncPollable;

wit_bindgen::generate!({
    world: "wasmtime:debugger/main",
    path: "wit",
    with: {
        "wasi:io/poll@0.2.6": wasip2::io::poll,
        "wasi:io/error@0.2.6": wasip2::io::error,
        "wasi:io/streams@0.2.6": wasip2::io::streams,
        "wasi:clocks/monotonic-clock@0.2.6": wasip2::clocks::monotonic_clock,
        "wasi:clocks/wall-clock@0.2.6": wasip2::clocks::wall_clock,
        "wasi:filesystem/types@0.2.6": wasip2::filesystem::types,
        "wasi:filesystem/preopens@0.2.6": wasip2::filesystem::preopens,
        "wasi:sockets/network@0.2.6": wasip2::sockets::network,
        "wasi:sockets/instance-network@0.2.6": wasip2::sockets::instance_network,
        "wasi:sockets/udp@0.2.6": wasip2::sockets::udp,
        "wasi:sockets/tcp@0.2.6": wasip2::sockets::tcp,
        "wasi:sockets/udp-create-socket@0.2.6": wasip2::sockets::udp_create_socket,
        "wasi:sockets/tcp-create-socket@0.2.6": wasip2::sockets::tcp_create_socket,
        "wasi:sockets/ip-name-lookup@0.2.6": wasip2::sockets::ip_name_lookup,
        "wasi:random/random@0.2.6": wasip2::random::random,
        "wasi:random/insecure@0.2.6": wasip2::random::insecure,
        "wasi:random/insecure-seed@0.2.6": wasip2::random::insecure_seed,
        "wasi:cli/stdin@0.2.6": wasip2::cli::stdin,
        "wasi:cli/stdout@0.2.6": wasip2::cli::stdout,
        "wasi:cli/stderr@0.2.6": wasip2::cli::stderr,
        "wasi:cli/terminal-input@0.2.6": wasip2::cli::terminal_input,
        "wasi:cli/terminal-output@0.2.6": wasip2::cli::terminal_output,
        "wasi:cli/terminal-stdin@0.2.6": wasip2::cli::terminal_stdin,
        "wasi:cli/terminal-stdout@0.2.6": wasip2::cli::terminal_stdout,
        "wasi:cli/terminal-stderr@0.2.6": wasip2::cli::terminal_stderr,
        "wasi:cli/environment@0.2.6": wasip2::cli::environment,
        "wasi:cli/exit@0.2.6": wasip2::cli::exit,
    }
});
pub(crate) use wasmtime::debugger::debuggee::*;

/// One "resumption", or period of execution, in the debuggee.
pub struct Resumption {
    future: EventFuture,
    pollable: Option<AsyncPollable>,
}

impl Resumption {
    pub fn continue_(d: &Debuggee, r: ResumptionValue) -> Self {
        let future = d.continue_(r);
        let pollable = Some(AsyncPollable::new(future.subscribe()));
        Resumption { future, pollable }
    }

    pub fn single_step(d: &Debuggee, r: ResumptionValue) -> Self {
        let future = d.single_step(r);
        let pollable = Some(AsyncPollable::new(future.subscribe()));
        Resumption { future, pollable }
    }

    pub async fn wait(&mut self) {
        if let Some(pollable) = self.pollable.as_mut() {
            pollable.wait_for().await;
        }
    }

    pub fn result(mut self, d: &Debuggee) -> std::result::Result<Event, Error> {
        // Drop the pollable first, since it's a child resource.
        let _ = self.pollable.take();
        EventFuture::finish(self.future, d)
    }
}
