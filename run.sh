#!/bin/bash
set -e

cargo build

echo "Setting up cap_net_admin"
sudo setcap cap_net_admin=eip ./target/debug/tcp-rust

echo "Running tcp-rust in background"
./target/debug/tcp-rust &

pid=$!

echo "tcp-rust pid: $pid"

echo "Set ip address"
# Set ip address to our network interface device
sudo ip addr add 192.168.0.1/24 dev tun0

echo "Make our interface online"
# Make it online!
sudo ip link set up dev tun0

echo "It's online!"

trap "kill $pid" INT TERM
wait $pid
