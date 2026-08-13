// Shared fixtures and helpers for the _state_tests_* files.
// Not embedder API.

const std = @import("std");
const boringssl = @import("boringssl");
const state = @import("../Connection.zig");
const Connection = state.Connection;
const EncryptionLevel = state.EncryptionLevel;
const PacketKeys = state.PacketKeys;
const QlogEvent = state.QlogEvent;
const QlogEventName = state.QlogEventName;
const SecretMaterial = state.SecretMaterial;
const short_packet_mod = state.short_packet_mod;

pub fn installTestApplicationWriteSecret(conn: *Connection) !void {
    var material: SecretMaterial = .{ .cipher_protocol_id = 0x1301 };
    material.secret_len = 32;
    try conn.installApplicationSecret(.write, material);
}

pub fn installTestApplicationReadSecret(conn: *Connection) !void {
    var material: SecretMaterial = .{ .cipher_protocol_id = 0x1301 };
    material.secret_len = 32;
    try conn.installApplicationSecret(.read, material);
}

pub fn installTestEarlyDataWriteSecret(conn: *Connection) void {
    var material: SecretMaterial = .{ .cipher_protocol_id = 0x1301 };
    material.secret_len = 32;
    conn.levels[EncryptionLevel.early_data.idx()].write = material;
}

pub fn installTestEarlyDataReadSecret(conn: *Connection) void {
    var material: SecretMaterial = .{ .cipher_protocol_id = 0x1301 };
    material.secret_len = 32;
    conn.levels[EncryptionLevel.early_data.idx()].read = material;
}

pub fn testEarlyDataPacketKeys() !PacketKeys {
    const secret: [32]u8 = @splat(0);
    return try short_packet_mod.derivePacketKeys(.aes128_gcm_sha256, &secret);
}

pub const TestQlogRecorder = struct {
    events: [128]QlogEvent = undefined,
    count: usize = 0,

    pub fn callback(user_data: ?*anyopaque, event: QlogEvent) void {
        const self: *TestQlogRecorder = @ptrCast(@alignCast(user_data.?));
        if (self.count >= self.events.len) return;
        self.events[self.count] = event;
        self.count += 1;
    }

    pub fn contains(self: *const TestQlogRecorder, name: QlogEventName) bool {
        for (self.events[0..self.count]) |event| {
            if (event.name == name) return true;
        }
        return false;
    }

    pub fn first(self: *const TestQlogRecorder, name: QlogEventName) ?QlogEvent {
        for (self.events[0..self.count]) |event| {
            if (event.name == name) return event;
        }
        return null;
    }

    pub fn countOf(self: *const TestQlogRecorder, name: QlogEventName) usize {
        var n: usize = 0;
        for (self.events[0..self.count]) |event| {
            if (event.name == name) n += 1;
        }
        return n;
    }
};

pub fn markTestMultipathNegotiated(conn: *Connection, max_path_id: u32) void {
    conn.enableMultipath(true);
    conn.local_transport_params.initial_max_path_id = max_path_id;
    conn.local_max_path_id = max_path_id;
    conn.cached_peer_transport_params = .{ .initial_max_path_id = max_path_id };
    conn.peer_max_path_id = max_path_id;
}
