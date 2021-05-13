package net.luminis.quic;

public enum Role {
    Client,
    Server;

    public Role other() {
        return this == Client? Server: Client;
    }
}
