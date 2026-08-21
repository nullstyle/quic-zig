//! Test root for benchmark helper modules.
//!
//! `zig build bench-test` runs these through the same build graph as
//! `zig build bench`, including BoringSSL's generated C module wiring.

test {
    _ = @import("connection_datagram.zig");
    _ = @import("e2e/counting_allocator.zig");
    _ = @import("e2e/fairness.zig");
    _ = @import("e2e/harness.zig");
    _ = @import("e2e/sim_net.zig");
    _ = @import("loss_ack.zig");
    _ = @import("packet_crypto.zig");
    _ = @import("path_flow.zig");
    _ = @import("report.zig");
    _ = @import("stream_reassembly.zig");
    _ = @import("tokens_lb.zig");
    _ = @import("transport_params.zig");
}
