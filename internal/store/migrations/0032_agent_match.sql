-- Matching a host agent's sockets to the sensor's connections looks them up
-- by remote end; retention deletes them by age, across every agent.
CREATE INDEX agent_connections_remote ON agent_connections (remote_ip, remote_port, last_seen);
CREATE INDEX agent_connections_seen ON agent_connections (last_seen);
